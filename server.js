// Minimal Express back end for the Juice Shop-style login page.
// Demonstrates: server-side validation, parameterized SQL (anti-SQLi),
// and bcrypt password hashing.
//
// Uses Node's BUILT-IN SQLite (node:sqlite), so there is nothing to compile
// and no native dependency to install. Requires Node.js 22.5+ (24+ recommended).

const express = require("express");
const bcrypt = require("bcryptjs");
const { DatabaseSync } = require("node:sqlite");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname))); // serves index.html, app.js, style.css

// --- In-memory SQLite database seeded with one user -------------------------
const db = new DatabaseSync(":memory:");
db.exec(
  "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT)"
);

// SECURE PASSWORD HANDLING: hash with bcrypt (cost factor 12) before storing.
// Plaintext passwords are never written to the database.
const seedEmail = "admin@juice-sh.op";
const seedHash = bcrypt.hashSync("admin123!", 12);
db.prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)").run(
  seedEmail,
  seedHash
);

// Server-side validation — authoritative. The client runs the same checks,
// but we re-run them here because the client can be bypassed.
function validateCredentials(email, password) {
  if (typeof email !== "string" || typeof password !== "string")
    return "Invalid input.";
  if (!email || !password) return "Email and password are required.";
  if (!email.includes("@")) return 'Email must contain "@".';
  if (password.length < 8) return "Password must be at least 8 characters.";
  return null;
}

app.post("/login", (req, res) => {
  const { email, password } = req.body || {};

  const error = validateCredentials(email, password);
  if (error) return res.status(400).json({ ok: false, error });

  // SQL INJECTION DEFENSE: the "?" placeholder binds `email` as DATA, not SQL.
  // Input like  ' OR 1=1--  is treated as a literal string and matches nothing.
  //
  // The VULNERABLE pattern (do NOT do this) would be string concatenation:
  //   db.prepare(`SELECT * FROM users WHERE email = '${email}'`)
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  // bcrypt.compareSync re-hashes the attempt and compares against the stored hash.
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    // The raw `email` is reflected back in this message. On its own, JSON is
    // just data — but the client renders it with innerHTML, which is where the
    // XSS actually fires (see app.js and README Part 3).
    return res.status(401).json({ ok: false, error: `Login failed for ${email}.` });
  }

  return res.json({ ok: true, message: `Welcome back, ${user.email}!` });
});

app.listen(PORT, () => {
  console.log(`Login demo running at http://localhost:${PORT}`);
});
