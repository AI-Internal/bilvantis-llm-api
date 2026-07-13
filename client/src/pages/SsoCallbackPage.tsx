import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { setToken } from '@/lib/api'
import { useI18n } from '@/i18n'

// Landing point for the Microsoft redirect (routes/sso.ts's callback route
// sends the browser here with #token=... or #sso_error=...). A URL fragment,
// not a query param, so the token never reaches server/proxy access logs.
export default function SsoCallbackPage() {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [error, setError] = useState<string | null>(null)
  // Effects can run twice in dev (StrictMode); only act on the fragment once.
  const handled = useRef(false)

  useEffect(() => {
    if (handled.current) return
    handled.current = true

    const params = new URLSearchParams(window.location.hash.replace(/^#/, ''))
    const token = params.get('token')
    const ssoError = params.get('sso_error')

    // Strip the fragment from history either way — it must not linger as a
    // back-button entry containing a session token.
    window.history.replaceState(null, '', window.location.pathname)

    if (token) {
      setToken(token)
      navigate('/', { replace: true })
      return
    }
    setError(ssoError ?? 'unknown_error')
  }, [navigate])

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm text-center">
        {error ? (
          <div className="rounded-3xl border bg-card p-6">
            <p className="text-sm text-destructive">{t('auth.ssoFailed')}</p>
            <button
              type="button"
              onClick={() => navigate('/', { replace: true })}
              className="mt-4 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              {t('auth.backToSignIn')}
            </button>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">{t('auth.ssoCompleting')}</p>
        )}
      </div>
    </div>
  )
}
