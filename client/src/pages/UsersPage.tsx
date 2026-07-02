import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useI18n } from '@/i18n'

interface TeamUser {
  id: number
  email: string
  role: 'admin' | 'member'
  createdAt: string
  hasKeys: number
}

// Admin-only team management. Server enforces admin (requireAdmin on /api/users)
// and blocks self-delete / last-admin removal; this page just surfaces those.
export default function UsersPage() {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<'admin' | 'member'>('member')
  const [error, setError] = useState('')
  const [newKey, setNewKey] = useState<{ email: string; key: string } | null>(null)

  const { data, isLoading } = useQuery<{ users: TeamUser[] }>({
    queryKey: ['users'],
    queryFn: () => apiFetch('/api/users'),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['users'] })

  const create = useMutation({
    mutationFn: () => apiFetch<{ user: TeamUser }>('/api/users', {
      method: 'POST',
      body: JSON.stringify({ email, password, role }),
    }),
    onSuccess: () => { setEmail(''); setPassword(''); setRole('member'); setError(''); invalidate() },
    onError: (e) => setError((e as Error).message),
  })

  const remove = useMutation({
    mutationFn: (id: number) => apiFetch(`/api/users/${id}`, { method: 'DELETE' }),
    onSuccess: invalidate,
    onError: (e) => setError((e as Error).message),
  })

  const rotate = useMutation({
    mutationFn: (u: TeamUser) => apiFetch<{ proxyKey: string }>(`/api/users/${u.id}/proxy-key`, { method: 'POST' })
      .then(r => ({ email: u.email, key: r.proxyKey })),
    onSuccess: (r) => setNewKey(r),
    onError: (e) => setError((e as Error).message),
  })

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-lg font-medium">{t('users.title')}</h1>
        <p className="text-sm text-muted-foreground mt-1">{t('users.description')}</p>
      </div>

      {/* Add teammate */}
      <form
        onSubmit={(e) => { e.preventDefault(); create.mutate() }}
        className="rounded-2xl border bg-card p-5 space-y-4 max-w-xl"
      >
        <h2 className="text-sm font-medium">{t('users.addTitle')}</h2>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label className="text-xs" htmlFor="u-email">{t('auth.email')}</Label>
            <Input id="u-email" type="email" autoComplete="off" value={email} onChange={e => setEmail(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs" htmlFor="u-password">{t('auth.password')}</Label>
            <Input id="u-password" type="password" autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} />
          </div>
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs" htmlFor="u-role">{t('users.role')}</Label>
          <select
            id="u-role"
            value={role}
            onChange={e => setRole(e.target.value as 'admin' | 'member')}
            className="h-9 w-full rounded-md border bg-background px-3 text-sm"
          >
            <option value="member">{t('users.roleMember')}</option>
            <option value="admin">{t('users.roleAdmin')}</option>
          </select>
        </div>
        {error && <p className="text-destructive text-xs">{error}</p>}
        <Button type="submit" disabled={create.isPending || !email || password.length < 8}>
          {create.isPending ? t('users.adding') : t('users.add')}
        </Button>
      </form>

      {/* One-time proxy key reveal after create/rotate */}
      {newKey && (
        <div className="rounded-2xl border border-emerald-500/40 bg-emerald-500/10 p-4 max-w-xl">
          <p className="text-xs text-muted-foreground">{t('users.keyForBefore')}<strong>{newKey.email}</strong>{t('users.keyForAfter')}</p>
          <code className="mt-2 block break-all rounded bg-background px-2 py-1 text-xs">{newKey.key}</code>
          <button className="mt-2 text-xs underline" onClick={() => setNewKey(null)}>{t('users.dismiss')}</button>
        </div>
      )}

      {/* Members */}
      <div className="rounded-2xl border bg-card overflow-hidden max-w-3xl">
        <div className="border-b px-5 py-3 text-sm font-medium">{t('users.membersTitle')}</div>
        {isLoading ? (
          <p className="px-5 py-4 text-sm text-muted-foreground">{t('users.loading')}</p>
        ) : (
          <ul className="divide-y">
            {(data?.users ?? []).map(u => (
              <li key={u.id} className="flex items-center justify-between gap-4 px-5 py-3">
                <div className="min-w-0">
                  <div className="truncate text-sm">{u.email}</div>
                  <div className="text-xs text-muted-foreground">
                    {u.role === 'admin' ? t('users.roleAdmin') : t('users.roleMember')}
                    {' · '}
                    {u.hasKeys} {t('users.keysLabel')}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <Button variant="ghost" size="sm" onClick={() => rotate.mutate(u)}>{t('users.rotateKey')}</Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-destructive"
                    onClick={() => { if (confirm(t('users.confirmDelete'))) remove.mutate(u.id) }}
                  >
                    {t('users.remove')}
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
