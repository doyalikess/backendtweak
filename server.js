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

if (!STRIPE_SECRET_KEY) {
  console.error("Missing STRIPE_SECRET_KEY");
}

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
  console.log("Database ready");
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

// ---------------- ADMIN AUTH ----------------
function requireAdmin(req, res, next) {
  const cookie = req.headers.cookie || "";
  if (cookie.includes("admin_auth=true")) return next();
  return res.status(401).json({ success: false, error: "Unauthorized" });
}

// ---------------- STRIPE WEBHOOK ----------------
app.post(
  "/webhook/stripe",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];

    if (!sig || !STRIPE_WEBHOOK_SECRET) {
      return res.status(400).send("Webhook error");
    }

    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("Webhook signature failed");
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

        console.log("License created:", key);
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
    res.json({
      status: "ok",
      mode: isTestMode ? "test" : "live",
      db: "postgresql",
    });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

app.post("/api/create-checkout", async (req, res) => {
  try {
    const price = 1499;

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: isTestMode
                ? "Tweakr Pro - TEST"
                : "Tweakr Pro - Lifetime License",
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

    res.json({ success: true, url: session.url });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

app.get("/api/license/:sessionId", async (req, res) => {
  const result = await pool.query(
    "SELECT license_key, created_at FROM licenses WHERE session_id=$1",
    [req.params.sessionId]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ success: false });
  }

  res.json({ success: true, ...result.rows[0] });
});

app.post("/api/activate", async (req, res) => {
  const { license_key, hwid } = req.body;

  if (!license_key || !hwid) {
    return res.json({ success: false });
  }

  const result = await pool.query(
    "SELECT * FROM licenses WHERE license_key=$1",
    [license_key]
  );

  if (result.rows.length === 0) {
    return res.json({ success: false, error: "Invalid key" });
  }

  const row = result.rows[0];

  if (row.activated && row.hwid !== hwid) {
    return res.json({
      success: false,
      error: "Activated on another device",
    });
  }

  if (!row.activated) {
    await pool.query(
      "UPDATE licenses SET activated=true, hwid=$1 WHERE license_key=$2",
      [hwid, license_key]
    );
  }

  res.json({ success: true, expires: "Lifetime" });
});

// ---------------- ADMIN AUTH ROUTES ----------------
app.post("/admin/login", (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    res.setHeader("Set-Cookie", "admin_auth=true; HttpOnly; Path=/");
    return res.json({ success: true });
  }
  res.json({ success: false });
});

app.post("/admin/logout", (req, res) => {
  res.setHeader("Set-Cookie", "admin_auth=false; Max-Age=0; Path=/");
  res.json({ success: true });
});

// ---------------- ADMIN API ----------------
app.get("/admin/api/licenses", requireAdmin, async (req, res) => {
  const result = await pool.query(
    "SELECT license_key, customer_email, activated, hwid, created_at FROM licenses ORDER BY id DESC"
  );
  res.json({ success: true, licenses: result.rows });
});

app.post("/admin/api/add", requireAdmin, async (req, res) => {
  const email = req.body.email || null;
  const key = generateLicenseKey();

  await pool.query(
    "INSERT INTO licenses (license_key, session_id, customer_email) VALUES ($1,$2,$3)",
    [key, "manual_" + Date.now(), email]
  );

  res.json({ success: true, license_key: key });
});

app.post("/admin/api/delete", requireAdmin, async (req, res) => {
  await pool.query(
    "DELETE FROM licenses WHERE license_key=$1",
    [req.body.license_key]
  );
  res.json({ success: true });
});

app.post("/admin/api/reset", requireAdmin, async (req, res) => {
  await pool.query(
    "UPDATE licenses SET activated=false, hwid=NULL WHERE license_key=$1",
    [req.body.license_key]
  );
  res.json({ success: true });
});

// ---------------- START ----------------
initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log("Server running on port", PORT);
      console.log("Mode:", isTestMode ? "TEST" : "LIVE");
    });
  })
  .catch((err) => {
    console.error("Startup failed", err);
    process.exit(1);
  });
