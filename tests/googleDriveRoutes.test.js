import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";

let server;
let baseUrl;
let Admin;
let originalFindById;
const oauthKeys = [
  "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI",
  "GOOGLE_DRIVE_CLIENT_ID", "GOOGLE_DRIVE_CLIENT_SECRET", "GOOGLE_DRIVE_REDIRECT_URI",
];
const originalEnv = { ...process.env };

before(async () => {
  // Importing routers must succeed even on a backend without OAuth configuration.
  for (const key of oauthKeys) delete process.env[key];
  const { default: router } = await import("../routes/authRoutes.js");
  for (const key of oauthKeys) delete process.env[key];
  process.env.JWT_SECRET = "test-only-secret";
  ({ default: Admin } = await import("../models/adminModel.js"));
  originalFindById = Admin.findById;
  Admin.findById = () => ({ select: async () => ({ _id: "test-admin" }) });
  const app = express();
  app.use(cookieParser());
  app.use("/api/auth", router);
  server = await new Promise((resolve) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  baseUrl = `http://127.0.0.1:${server.address().port}/api/auth/google-drive`;
});

after(async () => {
  if (Admin) Admin.findById = originalFindById;
  for (const key of [...oauthKeys, "JWT_SECRET"]) {
    if (originalEnv[key] === undefined) delete process.env[key];
    else process.env[key] = originalEnv[key];
  }
  if (server) await new Promise((resolve) => server.close(resolve));
});

const connect = () => fetch(`${baseUrl}/connect`, {
  headers: { Authorization: `Bearer ${jwt.sign({ id: "test-admin" }, process.env.JWT_SECRET)}` },
});

test("connect route exists and requires authentication", async () => {
  const response = await fetch(`${baseUrl}/connect`);
  assert.equal(response.status, 401);
  assert.match((await response.json()).message, /Not authorized/);
});

test("missing OAuth settings produce actionable JSON without crashing", async () => {
  const response = await connect();
  assert.equal(response.status, 503);
  const body = await response.json();
  assert.equal(body.success, false);
  assert.match(body.message, /GOOGLE_CLIENT_ID/);
});

test("configured connect returns an OAuth URL and signed state", async () => {
  process.env.GOOGLE_CLIENT_ID = "test-client";
  process.env.GOOGLE_CLIENT_SECRET = "test-secret";
  process.env.GOOGLE_REDIRECT_URI = "https://backend.example/api/auth/google-drive/callback";
  const response = await connect();
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.authUrl, body.authorizationUrl);
  const url = new URL(body.authUrl);
  assert.equal(url.hostname, "accounts.google.com");
  assert.equal(url.searchParams.get("client_id"), "test-client");
  assert.equal(url.searchParams.get("redirect_uri"), process.env.GOOGLE_REDIRECT_URI);
  assert.equal(jwt.verify(url.searchParams.get("state"), process.env.JWT_SECRET).adminId, "test-admin");
});

test("callback route handles missing OAuth parameters", async () => {
  const response = await fetch(`${baseUrl}/callback`, { redirect: "manual" });
  assert.equal(response.status, 302);
  assert.equal(new URL(response.headers.get("location")).searchParams.get("googleDrive"), "error");
});
