// Built to build/preload-popover.cjs. Exposes the minimal IPC surface the
// popover UI needs — no Node access in the renderer.
import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('bilvantis', {
  snapshot: () => ipcRenderer.invoke('bilvantis:snapshot'),
  openDashboard: () => ipcRenderer.invoke('bilvantis:open-dashboard'),
  copyBaseUrl: () => ipcRenderer.invoke('bilvantis:copy-base-url'),
  copyApiKey: () => ipcRenderer.invoke('bilvantis:copy-api-key'),
  setLoginItem: (open: boolean) => ipcRenderer.invoke('bilvantis:set-login-item', open),
  quit: () => ipcRenderer.invoke('bilvantis:quit'),
  onRefresh: (cb: () => void) => ipcRenderer.on('bilvantis:refresh', cb),
});
