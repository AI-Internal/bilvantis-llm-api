import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './api'

// Reads the shared auth-status cache (same queryKey the navbar/AuthGate populate,
// so no extra request) to gate admin-only UI. Shared routing/catalog config is
// admin-managed on the server; members get a read-only view.
export function useIsAdmin(): boolean {
  const { data } = useQuery<{ role: string | null }>({
    queryKey: ['auth-status'],
    queryFn: () => apiFetch('/api/auth/status'),
  })
  return data?.role === 'admin'
}
