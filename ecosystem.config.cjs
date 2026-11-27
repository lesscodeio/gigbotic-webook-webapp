const path = require("node:path");
const os = require("node:os");

const HOME_DIR = process.env.HOME || os.homedir();
const BIN_DIR = path.join(HOME_DIR, ".local", "bin");

module.exports = {
  apps: [
    {
      name: "gigbotic-managed-relay",
      script: path.join(__dirname, "server.mjs"),
      cwd: __dirname,
      interpreter: process.env.NODE_BIN || path.join(BIN_DIR, "node"),
      autorestart: true,
      max_restarts: 20,
      restart_delay: 2500,
      max_memory_restart: "512M",
      out_file: path.join(__dirname, "logs", "server.log"),
      error_file: path.join(__dirname, "logs", "server.log"),
      merge_logs: true,
      env: {
        HOME: HOME_DIR,
        XDG_CONFIG_HOME: path.join(HOME_DIR, ".config"),
        XDG_CACHE_HOME: path.join(HOME_DIR, ".cache"),
        XDG_DATA_HOME: path.join(HOME_DIR, ".local", "share"),
        UI_HOST: process.env.UI_HOST || "127.0.0.1",
        UI_PORT: process.env.UI_PORT || "3450",
        PATH: `${BIN_DIR}:${process.env.PATH || "/usr/local/bin:/usr/bin:/bin"}`,
      },
    },
  ],
};
