import crypto from 'crypto';
import { getDb } from '../db/index.js';
import { createUser, createSession, isAllowedEmailDomain, type SessionUser, type Role } from './auth.js';

// Microsoft Entra ID (Azure AD) SSO: a hand-rolled OIDC authorization-code +
// PKCE flow using only Node built-ins and fetch, matching this codebase's
// existing auth style (no passport/openid-client/jose dependency). The flow
// ends by calling the existing createSession(), so requireAuth and every
// downstream route need zero changes — SSO is just a second way to obtain
// the same opaque bearer token password login already produces.
//
// Multi-tenant by design: the app is registered in Azure as "Accounts in any
// organizational directory", so sign-in works from any Entra tenant (not just
// one pinned tenant) — access is gated purely by isAllowedEmailDomain(),
// which provisionSsoUser() already enforces.

const STATE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const JWKS_TTL_MS = 60 * 60 * 1000; // 1 hour

export function ssoEnabled(): boolean {
  return process.env.SSO_ENABLED === 'true';
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not configured`);
  return value;
}

function clientId(): string {
  return requiredEnv('AZURE_AD_CLIENT_ID');
}

function clientSecret(): string {
  return requiredEnv('AZURE_AD_CLIENT_SECRET');
}

function stateSecret(): string {
  return requiredEnv('SSO_STATE_SECRET');
}

export function publicAppUrl(): string {
  return requiredEnv('PUBLIC_APP_URL').replace(/\/$/, '');
}

// "organizations" is Microsoft's multi-tenant pseudo-tenant segment: it
// accepts sign-in from any Entra organizational tenant, matching the
// "AzureADMultipleOrgs" account type set on the App Registration. The JWKS
// signing keys are identical across the tenant-specific/common/organizations
// endpoint variants (one global key set backs the v2.0 endpoint), so this
// isn't tenant-specific in any way that matters for verification either.
function authorizeEndpoint(): string {
  return 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize';
}

function tokenEndpoint(): string {
  return 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token';
}

function jwksUri(): string {
  return 'https://login.microsoftonline.com/organizations/discovery/v2.0/keys';
}

export function redirectUri(): string {
  return `${publicAppUrl()}/api/auth/sso/callback`;
}

// ── PKCE + state/nonce transaction ──────────────────────────────────────────
// There's no server-side session yet at this point in the flow (the caller
// isn't logged in), so the transaction is carried across the redirect to
// Microsoft and back as a signed, self-contained cookie value instead.

export interface SsoTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
  exp: number;
}

export function createTransaction(): SsoTransaction {
  return {
    state: crypto.randomBytes(16).toString('hex'),
    nonce: crypto.randomBytes(16).toString('hex'),
    codeVerifier: crypto.randomBytes(32).toString('base64url'),
    exp: Date.now() + STATE_TTL_MS,
  };
}

function codeChallengeFor(codeVerifier: string): string {
  return crypto.createHash('sha256').update(codeVerifier).digest('base64url');
}

export function signTransaction(txn: SsoTransaction): string {
  const payload = Buffer.from(JSON.stringify(txn)).toString('base64url');
  const sig = crypto.createHmac('sha256', stateSecret()).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

export function verifyTransaction(cookieValue: string | undefined): SsoTransaction | null {
  if (!cookieValue) return null;
  const [payload, sig] = cookieValue.split('.');
  if (!payload || !sig) return null;

  const expectedSig = crypto.createHmac('sha256', stateSecret()).update(payload).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;

  let txn: SsoTransaction;
  try {
    txn = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (typeof txn.exp !== 'number' || txn.exp < Date.now()) return null;
  return txn;
}

export function buildAuthorizeUrl(txn: SsoTransaction): string {
  const params = new URLSearchParams({
    client_id: clientId(),
    response_type: 'code',
    redirect_uri: redirectUri(),
    response_mode: 'query',
    scope: 'openid profile email',
    state: txn.state,
    nonce: txn.nonce,
    code_challenge: codeChallengeFor(txn.codeVerifier),
    code_challenge_method: 'S256',
  });
  return `${authorizeEndpoint()}?${params.toString()}`;
}

// ── Token exchange + ID token verification ──────────────────────────────────

interface TokenResponse {
  id_token: string;
  token_type: string;
}

async function exchangeCodeForTokens(code: string, codeVerifier: string): Promise<TokenResponse> {
  const body = new URLSearchParams({
    client_id: clientId(),
    client_secret: clientSecret(),
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri(),
    code_verifier: codeVerifier,
  });
  const res = await fetch(tokenEndpoint(), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Microsoft token exchange failed (${res.status}): ${text}`);
  }
  return res.json() as Promise<TokenResponse>;
}

interface Jwk {
  kid: string;
  kty: string;
  n: string;
  e: string;
}

let jwksCache: { keys: Jwk[]; fetchedAt: number } | null = null;

async function getJwks(forceRefresh = false): Promise<Jwk[]> {
  if (!forceRefresh && jwksCache && Date.now() - jwksCache.fetchedAt < JWKS_TTL_MS) {
    return jwksCache.keys;
  }
  const res = await fetch(jwksUri());
  if (!res.ok) throw new Error(`Failed to fetch Microsoft signing keys: ${res.status}`);
  const body = (await res.json()) as { keys: Jwk[] };
  jwksCache = { keys: body.keys, fetchedAt: Date.now() };
  return body.keys;
}

function decodeJwtPart(part: string): any {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

export interface SsoClaims {
  email: string;
  oid: string;
  tid: string;
}

async function verifyIdToken(idToken: string, expectedNonce: string): Promise<SsoClaims> {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Malformed ID token');
  const [headerPart, payloadPart, signaturePart] = parts;
  const header = decodeJwtPart(headerPart);
  const payload = decodeJwtPart(payloadPart);

  if (header.alg !== 'RS256') throw new Error(`Unsupported ID token algorithm: ${header.alg}`);

  let jwks = await getJwks();
  let jwk = jwks.find((k) => k.kid === header.kid);
  if (!jwk) {
    // Key rotated since our last fetch/cache — refresh once before giving up.
    jwks = await getJwks(true);
    jwk = jwks.find((k) => k.kid === header.kid);
  }
  if (!jwk) throw new Error('No matching Microsoft signing key for this ID token');

  const publicKey = crypto.createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e }, format: 'jwk' });
  const signedData = Buffer.from(`${headerPart}.${payloadPart}`);
  const signature = Buffer.from(signaturePart, 'base64url');
  if (!crypto.verify('RSA-SHA256', signedData, publicKey, signature)) {
    throw new Error('ID token signature verification failed');
  }

  // Multi-tenant issuer check: self-consistent (matches the token's own `tid`)
  // rather than pinned to one known tenant, since sign-in can come from any
  // Entra org. Safe because the RS256 signature above is already verified
  // against Microsoft's real public keys — only Microsoft can produce a
  // validly-signed token, and it always sets `tid` to the real signed-in
  // user's actual tenant, so this can't be spoofed by an attacker.
  const expectedIssuer = `https://login.microsoftonline.com/${payload.tid}/v2.0`;
  if (payload.iss !== expectedIssuer) throw new Error('Unexpected ID token issuer');
  if (payload.aud !== clientId()) throw new Error('Unexpected ID token audience');
  if (typeof payload.exp !== 'number' || payload.exp * 1000 < Date.now()) throw new Error('ID token expired');
  if (payload.nonce !== expectedNonce) throw new Error('ID token nonce mismatch');

  const email: string | undefined = payload.email ?? payload.preferred_username;
  if (!email) throw new Error('ID token has no email or preferred_username claim');

  return { email, oid: payload.oid, tid: payload.tid };
}

// ── User provisioning ────────────────────────────────────────────────────────

interface UserRow {
  id: number;
  email: string;
  role: Role;
}

function findUserBySsoSubject(oid: string): UserRow | undefined {
  return getDb().prepare('SELECT id, email, role FROM users WHERE sso_subject = ?').get(oid) as UserRow | undefined;
}

function findUserByEmail(email: string): UserRow | undefined {
  return getDb()
    .prepare('SELECT id, email, role FROM users WHERE email = ?')
    .get(email.trim().toLowerCase()) as UserRow | undefined;
}

function linkSsoIdentity(userId: number, claims: SsoClaims): void {
  getDb()
    .prepare(`UPDATE users SET auth_provider = 'microsoft', sso_subject = ?, sso_tenant_id = ? WHERE id = ?`)
    .run(claims.oid, claims.tid, userId);
}

/**
 * Find-or-create the local user for a verified Microsoft identity, then
 * return it for session creation. `sso_subject` (Microsoft's `oid`) is the
 * primary lookup key — stable across email/UPN renames — falling back to
 * email, which also lets an existing password account link itself to
 * Microsoft on first SSO login instead of spawning a duplicate.
 */
export function provisionSsoUser(claims: SsoClaims): SessionUser {
  const bySubject = findUserBySsoSubject(claims.oid);
  if (bySubject) return { userId: bySubject.id, email: bySubject.email, role: bySubject.role };

  const byEmail = findUserByEmail(claims.email);
  if (byEmail) {
    linkSsoIdentity(byEmail.id, claims);
    return { userId: byEmail.id, email: byEmail.email, role: byEmail.role };
  }

  if (!isAllowedEmailDomain(claims.email)) {
    const err = new Error(`Email domain not allowed: ${claims.email}`) as any;
    err.code = 'domain_not_allowed';
    throw err;
  }

  // Reuse the existing, already-tested account-creation path (including its
  // first-user-becomes-admin bootstrap) with a random, never-shown password —
  // password login for this account is a practical impossibility since the
  // value is never stored or returned anywhere else.
  const randomPassword = crypto.randomBytes(32).toString('hex');
  const user = createUser(claims.email, randomPassword, 'member');
  linkSsoIdentity(user.userId, claims);
  return user;
}

/** Complete the SSO flow: exchange the code, verify the token, provision the user, mint a session. */
export async function completeSsoLogin(code: string, txn: SsoTransaction): Promise<string> {
  const tokens = await exchangeCodeForTokens(code, txn.codeVerifier);
  const claims = await verifyIdToken(tokens.id_token, txn.nonce);
  const user = provisionSsoUser(claims);
  return createSession(user.userId);
}
