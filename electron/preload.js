const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("gnSlopDesktop", {
  platform: process.platform,
  onBackendExit(callback) {
    ipcRenderer.on("backend-exit", (_event, code) => callback(code));
  },
});
