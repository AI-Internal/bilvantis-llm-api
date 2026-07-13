import { Router } from 'express';
import type { Request, Response } from 'express';
import {
  ssoEnabled,
  createTransaction,
  signTransaction,
  verifyTransaction,
  buildAuthorizeUrl,
  completeSsoLogin,
  publicAppUrl,
} from '../services/sso.js';

export const ssoRouter = Router();

const TXN_COOKIE = 'sso_txn';
const TXN_COOKIE_PATH = '/api/auth/sso';

// No cookie-parser dependency in this codebase — a minimal manual parse of
// the raw Cookie header is all we need for the one cookie this flow sets.
function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return undefined;
}

function clearTxnCookie(res: Response): void {
  res.clearCookie(TXN_COOKIE, { path: TXN_COOKIE_PATH });
}

function redirectWithError(res: Response, code: string): void {
  res.redirect(302, `${publicAppUrl()}/auth/callback#sso_error=${encodeURIComponent(code)}`);
}

// Not "SSO isn't set up" vs "SSO route doesn't exist" — both 404 the same way
// so an unconfigured install reveals nothing about whether SSO is planned.
ssoRouter.use((req: Request, res: Response, next) => {
  if (!ssoEnabled()) {
    res.status(404).json({ error: { message: 'Not found', type: 'not_found_error' } });
    return;
  }
  next();
});

ssoRouter.get('/login', (_req: Request, res: Response) => {
  const txn = createTransaction();
  res.cookie(TXN_COOKIE, signTransaction(txn), {
    httpOnly: true,
    secure: true,
    // The callback is reached via a top-level cross-site redirect from
    // login.microsoftonline.com — `sameSite: 'strict'` would drop the cookie.
    sameSite: 'lax',
    maxAge: 5 * 60 * 1000,
    path: TXN_COOKIE_PATH,
  });
  res.redirect(302, buildAuthorizeUrl(txn));
});

ssoRouter.get('/callback', async (req: Request, res: Response) => {
  const txn = verifyTransaction(readCookie(req, TXN_COOKIE));
  clearTxnCookie(res);

  if (typeof req.query.error === 'string') {
    redirectWithError(res, 'access_denied');
    return;
  }
  if (!txn) {
    redirectWithError(res, 'invalid_transaction');
    return;
  }
  if (req.query.state !== txn.state) {
    redirectWithError(res, 'state_mismatch');
    return;
  }
  const code = req.query.code;
  if (typeof code !== 'string') {
    redirectWithError(res, 'missing_code');
    return;
  }

  try {
    const token = await completeSsoLogin(code, txn);
    res.redirect(302, `${publicAppUrl()}/auth/callback#token=${encodeURIComponent(token)}`);
  } catch (err: any) {
    redirectWithError(res, err?.code === 'domain_not_allowed' ? 'domain_not_allowed' : 'login_failed');
  }
});
