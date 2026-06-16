const { app, BrowserWindow } = require("electron");
const path = require("path");

function createWindow() {
  if (!app.isReady()) return;

  const win = new BrowserWindow({
    width: 1200,
    height: 750,
    frame: false,
    transparent: true,
    resizable: false,
    backgroundColor: "#00000000",
    icon: path.join(__dirname, "assets/logo.png"),
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    }
  });

  win.loadFile("renderer/index.html");

  global.win = win;
}

app.whenReady().then(() => {
  createWindow();
});

app.on("window-all-closed", () => {
  if (process.platform === "darwin") return;
  app.quit();
});