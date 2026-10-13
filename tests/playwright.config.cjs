const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: ".",
  testMatch: "browser-smoke.spec.cjs",
  timeout: 30000,
  retries: 0,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:8080",
    browserName: "chromium",
    headless: true,
    trace: "retain-on-failure"
  }
});
