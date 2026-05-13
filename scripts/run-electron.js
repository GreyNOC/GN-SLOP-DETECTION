const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const electronDir = path.join(root, "node_modules", "electron");
const installScript = path.join(electronDir, "install.js");
const electronCli = path.join(electronDir, "cli.js");
const env = {
  ...process.env,
  electron_config_cache: path.join(root, ".electron-cache"),
  ELECTRON_BUILDER_CACHE: path.join(root, ".electron-builder-cache"),
};

function runNode(args) {
  return spawnSync(process.execPath, args, {
    cwd: root,
    env,
    stdio: "inherit",
  });
}

if (!fs.existsSync(installScript) || !fs.existsSync(electronCli)) {
  console.error("Electron dependencies are missing. Run npm install first.");
  process.exit(1);
}

const installResult = runNode([installScript]);
if (installResult.status !== 0) {
  process.exit(installResult.status ?? 1);
}

const electronArgs = process.argv.slice(2);
const runResult = runNode([electronCli, ...(electronArgs.length ? electronArgs : ["."])]);
process.exit(runResult.status ?? 1);
