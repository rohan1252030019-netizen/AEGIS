import { app, BrowserWindow, shell } from 'electron';
import { spawn } from 'node:child_process';
import path from 'node:path';

const isPackaged = app.isPackaged;
const port = Number(process.env.AEGIS_FRONTEND_PORT || 3000);
const webUrl = process.env.AEGIS_WEB_URL || `http://127.0.0.1:${port}`;
let nextProcess;

function nextCommand() {
  if (isPackaged) {
    return {
      command: process.execPath,
      args: [path.join(app.getAppPath(), 'node_modules', 'next', 'dist', 'bin', 'next'), 'start', '-p', String(port), '-H', '127.0.0.1'],
      env: { ...process.env, ELECTRON_RUN_AS_NODE: '1', NODE_ENV: 'production' },
    };
  }

  const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  return {
    command: npmCommand,
    args: ['run', 'dev', '--', '-p', String(port), '-H', '127.0.0.1'],
    env: { ...process.env, NODE_ENV: 'development' },
  };
}

function startWebServer() {
  const { command, args, env } = nextCommand();
  nextProcess = spawn(command, args, {
    cwd: app.getAppPath(),
    env,
    stdio: isPackaged ? 'ignore' : 'inherit',
    windowsHide: true,
  });
  nextProcess.on('error', (error) => console.error('Unable to start AEGIS web server:', error));
}

async function waitForWebServer(timeoutMs = 30000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await fetch(webUrl);
      if (response.ok || response.status < 500) return;
    } catch {
      // The Next.js server is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`AEGIS web server did not start at ${webUrl}`);
}

async function createWindow() {
  await waitForWebServer();
  const window = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: '#16181D',
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  window.once('ready-to-show', () => window.show());
  window.webContents.setWindowOpenHandler(({ url }) => {
    if (!url.startsWith(webUrl)) shell.openExternal(url);
    return { action: 'deny' };
  });
  await window.loadURL(webUrl);
}

app.whenReady().then(async () => {
  startWebServer();
  try {
    await createWindow();
  } catch (error) {
    console.error(error);
    app.quit();
  }
});

app.on('window-all-closed', () => {
  if (nextProcess && !nextProcess.killed) nextProcess.kill();
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  if (nextProcess && !nextProcess.killed) nextProcess.kill();
});

app.on('activate', async () => {
  if (BrowserWindow.getAllWindows().length === 0) await createWindow();
});