const { app, BrowserWindow, dialog, shell } = require("electron");
const { spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const net = require("net");
const path = require("path");

let backendProcess = null;
let backendBaseUrl = null;
let mainWindow = null;

function repoRoot() {
  return path.resolve(__dirname, "..");
}

function backendExecutableName() {
  return process.platform === "win32" ? "gn-slop-backend.exe" : "gn-slop-backend";
}

function packagedBackendPath() {
  return path.join(process.resourcesPath, "backend", backendExecutableName());
}

function sourcePythonCommand() {
  if (process.env.GN_SLOP_PYTHON) {
    return process.env.GN_SLOP_PYTHON;
  }
  if (process.platform === "win32") {
    const venvPython = path.join(repoRoot(), ".venv", "Scripts", "python.exe");
    return fs.existsSync(venvPython) ? venvPython : "python";
  }
  const venvPython = path.join(repoRoot(), ".venv", "bin", "python");
  return fs.existsSync(venvPython) ? venvPython : "python3";
}

function backendCommand() {
  const packagedBackend = packagedBackendPath();
  if (app.isPackaged && fs.existsSync(packagedBackend)) {
    return {
      command: packagedBackend,
      args: [],
      cwd: path.dirname(packagedBackend),
    };
  }

  return {
    command: sourcePythonCommand(),
    args: ["-B", "-m", "app.desktop_server"],
    cwd: repoRoot(),
  };
}

function findOpenPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

function healthCheck(url) {
  return new Promise((resolve) => {
    const request = http.get(`${url}/health`, (response) => {
      response.resume();
      resolve(response.statusCode === 200);
    });
    request.setTimeout(600, () => {
      request.destroy();
      resolve(false);
    });
    request.on("error", () => resolve(false));
  });
}

async function waitForBackend(url) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (await healthCheck(url)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("The local analysis engine did not start in time.");
}

async function startBackend() {
  const port = await findOpenPort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const backend = backendCommand();
  const env = {
    ...process.env,
    APP_HOST: "127.0.0.1",
    APP_PORT: String(port),
    PYTHONUNBUFFERED: "1",
    UVICORN_LOG_LEVEL: "warning",
  };

  backendProcess = spawn(backend.command, backend.args, {
    cwd: backend.cwd,
    env,
    stdio: app.isPackaged ? "ignore" : "inherit",
    windowsHide: true,
  });

  backendProcess.once("exit", (code) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send("backend-exit", code);
    }
  });

  await waitForBackend(baseUrl);
  backendBaseUrl = baseUrl;
  return baseUrl;
}

function stopBackend() {
  if (!backendProcess || backendProcess.killed) {
    return;
  }
  backendProcess.kill();
  backendProcess = null;
  backendBaseUrl = null;
}

function isSafeExternalUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

function openExternalSafely(url) {
  if (isSafeExternalUrl(url)) {
    shell.openExternal(url);
  }
}

function createWindow(baseUrl) {
  mainWindow = new BrowserWindow({
    width: 1320,
    height: 860,
    minWidth: 1040,
    minHeight: 700,
    backgroundColor: "#101216",
    title: "GreyNOC Slop Detection",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      preload: path.join(__dirname, "preload.js"),
    },
  });

  mainWindow.removeMenu();
  mainWindow.loadURL(baseUrl);

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    openExternalSafely(url);
    return { action: "deny" };
  });

  mainWindow.webContents.on("will-navigate", (event, url) => {
    if (!url.startsWith(baseUrl)) {
      event.preventDefault();
      openExternalSafely(url);
    }
  });
}

app.whenReady().then(async () => {
  try {
    const baseUrl = await startBackend();
    createWindow(baseUrl);
  } catch (error) {
    dialog.showErrorBox("GreyNOC Slop Detection", error.message);
    app.quit();
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("activate", async () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    const baseUrl = backendBaseUrl || (await startBackend());
    createWindow(baseUrl);
  }
});

app.on("before-quit", stopBackend);
