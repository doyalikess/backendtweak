"use strict";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");
const Stripe = require("stripe");

const app = express();

// ---------------- CONFIG ----------------
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = "9923";

const stripe = new Stripe(STRIPE_SECRET_KEY, { apiVersion: "2024-06-20" });
const isTestMode = STRIPE_SECRET_KEY.startsWith("sk_test_");

// ---------------- DATABASE ----------------
const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ||
    "postgresql://tweakr_db_user:3XwJoMz3SQBh7HsQh6mMnlkTAxB20jiF@dpg-d63n4cer433s73d459eg-a/tweakr_db",
  ssl: { rejectUnauthorized: false },
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS licenses (
      id SERIAL PRIMARY KEY,
      license_key VARCHAR(100) UNIQUE NOT NULL,
      session_id VARCHAR(100) UNIQUE NOT NULL,
      customer_email VARCHAR(255),
      amount_total INTEGER,
      currency VARCHAR(10),
      hwid VARCHAR(100),
      activated BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

function generateLicenseKey() {
  const prefix = "TWEAK";
  const random = crypto.randomBytes(8).toString("hex").toUpperCase();
  const checksum = crypto
    .createHash("sha256")
    .update(prefix + random)
    .digest("hex")
    .slice(0, 6)
    .toUpperCase();
  return `${prefix}-${random}-${checksum}`;
}

// ---------------- MIDDLEWARE ----------------
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Admin auth middleware
app.use((req, res, next) => {
  if (!req.path.startsWith("/admin")) return next();
  if (req.path === "/admin/login") return next();

  const auth = req.headers.cookie && req.headers.cookie.includes("admin_auth=true");
  if (!auth) return res.redirect("/admin/login");

  next();
});

// ---------------- STRIPE WEBHOOK ----------------
app.post(
  "/webhook/stripe",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    if (!sig || !STRIPE_WEBHOOK_SECRET)
      return res.status(400).send("Webhook error");

    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      return res.status(400).send("Bad signature");
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const existing = await pool.query(
        "SELECT id FROM licenses WHERE session_id=$1",
        [session.id]
      );

      if (existing.rows.length === 0) {
        const key = generateLicenseKey();
        await pool.query(
          `INSERT INTO licenses 
          (license_key, session_id, customer_email, amount_total, currency)
          VALUES ($1,$2,$3,$4,$5)`,
          [
            key,
            session.id,
            session.customer_email,
            session.amount_total,
            session.currency,
          ]
        );
      }
    }

    res.json({ received: true });
  }
);

// ---------------- PUBLIC ROUTES ----------------
app.get("/", (req, res) => {
  res.send("Tweakr License Server Online");
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok" });
  } catch {
    res.status(500).json({ status: "error" });
  }
});

app.post("/api/create-checkout", async (req, res) => {
  const price = 1499;

  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    payment_method_types: ["card"],
    line_items: [
      {
        price_data: {
          currency: "usd",
          product_data: {
            name: "Tweakr Pro - Lifetime License",
            description: "HWID locked Windows optimization tool",
          },
          unit_amount: price,
        },
        quantity: 1,
      },
    ],
    success_url:
      "https://tweakr.store/#download?success=true&session_id={CHECKOUT_SESSION_ID}",
    cancel_url: "https://tweakr.store/#download?canceled=true",
  });

  res.json({ url: session.url });
});

app.get("/api/license/:sessionId", async (req, res) => {
  const result = await pool.query(
    "SELECT license_key, created_at FROM licenses WHERE session_id=$1",
    [req.params.sessionId]
  );

  if (result.rows.length === 0)
    return res.status(404).json({ error: "Not found" });

  res.json(result.rows[0]);
});

app.post("/api/activate", async (req, res) => {
  const { license_key, hwid } = req.body;

  const result = await pool.query(
    "SELECT * FROM licenses WHERE license_key=$1",
    [license_key]
  );

  if (result.rows.length === 0)
    return res.json({ success: false, error: "Invalid key" });

  const row = result.rows[0];

  if (row.activated && row.hwid !== hwid)
    return res.json({
      success: false,
      error: "Activated on another device",
    });

  if (!row.activated) {
    await pool.query(
      "UPDATE licenses SET activated=true, hwid=$1 WHERE license_key=$2",
      [hwid, license_key]
    );
  }

  res.json({ success: true });
});

// ---------------- ADMIN LOGIN ----------------
app.get("/admin/login", (req, res) => {
  res.send(adminLoginHTML());
});

app.post("/admin/login", (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    res.setHeader("Set-Cookie", "admin_auth=true; HttpOnly");
    return res.redirect("/admin");
  }
  res.send("Wrong password");
});

app.get("/admin/logout", (req, res) => {
  res.setHeader("Set-Cookie", "admin_auth=false; Max-Age=0");
  res.redirect("/admin/login");
});

// ---------------- ADMIN DASHBOARD ----------------
app.get("/admin", async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM licenses ORDER BY id DESC LIMIT 100"
  );
  res.send(adminDashboardHTML(result.rows));
});

app.post("/admin/create", async (req, res) => {
  const key = generateLicenseKey();
  await pool.query(
    "INSERT INTO licenses (license_key, session_id, customer_email) VALUES ($1,$2,$3)",
    [key, "manual_" + Date.now(), req.body.email || null]
  );
  res.redirect("/admin");
});

app.post("/admin/delete", async (req, res) => {
  await pool.query("DELETE FROM licenses WHERE license_key=$1", [
    req.body.license_key,
  ]);
  res.redirect("/admin");
});

app.post("/admin/reset", async (req, res) => {
  await pool.query(
    "UPDATE licenses SET activated=false, hwid=NULL WHERE license_key=$1",
    [req.body.license_key]
  );
  res.redirect("/admin");
});

// ---------------- HTML TEMPLATES ----------------
function adminLoginHTML() {
  return `
  <html>
  <head>
    <title>Tweakr Admin Login</title>
    <style>
      body{background:#0f1117;color:#fff;font-family:Arial;text-align:center;padding:100px}
      input{padding:10px;font-size:16px}
      button{padding:10px 20px;background:#1e90ff;border:none;color:#fff;cursor:pointer}
    </style>
  </head>
  <body>
    <h2>Tweakr Admin</h2>
    <form method="POST">
      <input type="password" name="password" placeholder="Password" required/>
      <br><br>
      <button>Login</button>
    </form>
  </body>
  </html>
  `;
}

function adminDashboardHTML(rows) {
  const table = rows
    .map(
      (r) => `
    <tr>
      <td>${r.license_key}</td>
      <td>${r.customer_email || ""}</td>
      <td>${r.activated}</td>
      <td>${r.hwid || ""}</td>
      <td>
        <form method="POST" action="/admin/delete">
          <input type="hidden" name="license_key" value="${r.license_key}">
          <button>Delete</button>
        </form>
        <form method="POST" action="/admin/reset">
          <input type="hidden" name="license_key" value="${r.license_key}">
          <button>Reset</button>
        </form>
      </td>
    </tr>`
    )
    .join("");

  return `
  <html>
  <head>
    <title>Tweakr Admin</title>
    <style>
      body{background:#0f1117;color:#fff;font-family:Arial;padding:40px}
      table{width:100%;border-collapse:collapse}
      td,th{border:1px solid #222;padding:8px}
      button{padding:5px 10px;background:#1e90ff;border:none;color:#fff;cursor:pointer}
      input{padding:6px}
      a{color:#1e90ff}
    </style>
  </head>
  <body>
    <h2>Tweakr Admin Panel</h2>
    <a href="/admin/logout">Logout</a>
    <h3>Create License</h3>
    <form method="POST" action="/admin/create">
      <input name="email" placeholder="Customer email">
      <button>Create</button>
    </form>
    <h3>Licenses</h3>
    <table>
      <tr>
        <th>Key</th>
        <th>Email</th>
        <th>Activated</th>
        <th>HWID</th>
        <th>Actions</th>
      </tr>
      ${table}
    </table>
  </body>
  </html>
  `;
}

// ---------------- START ----------------
initDB().then(() => {
  app.listen(PORT, () => {
    console.log("Server running on port", PORT);
  });
});
