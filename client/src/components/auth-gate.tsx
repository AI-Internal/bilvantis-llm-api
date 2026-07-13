import { useEffect, useState, type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch, setToken, UNAUTHORIZED_EVENT } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useI18n } from '@/i18n'

interface AuthStatus {
  needsSetup: boolean
  authenticated: boolean
  email: string | null
  role: 'admin' | 'member' | null
  allowedEmailDomains: string[]
  ssoEnabled: boolean
}

function Centered({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm">{children}</div>
    </div>
  )
}

function AuthForm({ initialMode, firstAccount, allowedDomains, ssoEnabled, onAuthed }: { initialMode: 'register' | 'login'; firstAccount: boolean; allowedDomains: string[]; ssoEnabled: boolean; onAuthed: () => void }) {
  const { t } = useI18n()
  const [mode, setMode] = useState<'register' | 'login'>(initialMode)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const isRegister = mode === 'register'

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const res = await apiFetch<{ token: string }>(isRegister ? '/api/auth/register' : '/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      })
      setToken(res.token)
      onAuthed()
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const heading = isRegister ? t('auth.createYourAccount') : t('auth.signIn')
  const description = isRegister
    ? (firstAccount ? t('auth.firstAccountDescription') : t('auth.registerDescription'))
    : t('auth.loginDescription')

  return (
    <Centered>
      <div className="mb-6 flex items-center gap-2">
        <img src="/bilvantis-logo.png" alt="Bilvantis" className="h-9 w-auto" />
        <span className="font-semibold tracking-tight text-4xl leading-none text-primary">Gateway</span>
      </div>
      <div className="rounded-3xl border bg-card p-6">
        <h1 className="text-base font-medium">{heading}</h1>
        <p className="text-xs text-muted-foreground mt-1 mb-4">{description}</p>
        {ssoEnabled && (
          <>
            <Button
              type="button"
              variant="outline"
              className="w-full mb-3"
              onClick={() => { window.location.href = '/api/auth/sso/login' }}
            >
              {t('auth.signInWithMicrosoft')}
            </Button>
            <div className="flex items-center gap-2 mb-3">
              <div className="h-px flex-1 bg-border" />
              <span className="text-[11px] text-muted-foreground">{t('auth.orDivider')}</span>
              <div className="h-px flex-1 bg-border" />
            </div>
          </>
        )}
        <form onSubmit={submit} className="space-y-3">
          <div className="space-y-1.5">
            <Label className="text-xs" htmlFor="auth-email">{t('auth.email')}</Label>
            <Input
              id="auth-email"
              type="email"
              autoComplete="username"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder={t('auth.emailPlaceholder')}
            />
            {isRegister && allowedDomains.length > 0 && !allowedDomains.includes('*') && (
              <p className="text-[11px] text-muted-foreground">
                {t('auth.allowedDomainsHint')} {allowedDomains.map(d => '@' + d).join(', ')}
              </p>
            )}
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs" htmlFor="auth-password">{t('auth.password')}</Label>
            <Input
              id="auth-password"
              type="password"
              autoComplete={isRegister ? 'new-password' : 'current-password'}
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder={isRegister ? t('auth.passwordPlaceholderSetup') : t('auth.passwordPlaceholderLogin')}
            />
          </div>
          {error && <p className="text-destructive text-xs">{error}</p>}
          <Button type="submit" className="w-full" disabled={busy || !email || !password}>
            {busy ? (isRegister ? t('auth.creating') : t('auth.signingIn')) : isRegister ? t('auth.createAccount') : t('auth.signIn')}
          </Button>
        </form>
        {/* The first-ever account must be a registration (it becomes the admin),
            so the toggle is hidden until at least one account exists. */}
        {!firstAccount && (
          <button
            type="button"
            onClick={() => { setError(''); setMode(isRegister ? 'login' : 'register') }}
            className="mt-4 w-full text-center text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            {isRegister ? t('auth.haveAccount') : t('auth.needAccount')}
          </button>
        )}
      </div>
    </Centered>
  )
}

export function AuthGate({ children }: { children: ReactNode }) {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const { data, isLoading, isError, refetch } = useQuery<AuthStatus>({
    queryKey: ['auth-status'],
    queryFn: () => apiFetch('/api/auth/status'),
    retry: false,
  })

  useEffect(() => {
    const handler = () => { refetch() }
    window.addEventListener(UNAUTHORIZED_EVENT, handler)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, handler)
  }, [refetch])

  function onAuthed() {
    // New session: drop any cached (unauthenticated) data and re-check status.
    queryClient.invalidateQueries()
    refetch()
  }

  if (isLoading) return <Centered><p className="text-sm text-muted-foreground text-center">{t('auth.loading')}</p></Centered>
  if (isError || !data) {
    return (
      <Centered>
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2.5 text-xs text-destructive">
          {t('auth.serverUnreachableBefore')}<code className="font-mono">npm run dev</code>{t('auth.serverUnreachableAfter')}
        </div>
      </Centered>
    )
  }

  if (!data.authenticated) {
    // First-ever visit (no users) defaults to Register and creates the admin;
    // afterwards default to Login but let visitors toggle to self-register.
    return <AuthForm initialMode={data.needsSetup ? 'register' : 'login'} firstAccount={data.needsSetup} allowedDomains={data.allowedEmailDomains ?? []} ssoEnabled={data.ssoEnabled} onAuthed={onAuthed} />
  }

  return <>{children}</>
}
