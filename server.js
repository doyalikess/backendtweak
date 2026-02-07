// server.js
"use strict";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg"); // Changed from sqlite3 to pg
const Stripe = require("stripe");

const app = express();

// -------------------- CONFIG --------------------
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const PORT = process.env.PORT || 3000;

if (!STRIPE_SECRET_KEY) {
  console.error("Missing STRIPE_SECRET_KEY");
}

const stripe = new Stripe(STRIPE_SECRET_KEY, { apiVersion: "2024-06-20" });
const isTestMode = STRIPE_SECRET_KEY.startsWith("sk_test_");

// -------------------- POSTGRESQL SETUP --------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://tweakr_db_user:3XwJoMz3SQBh7HsQh6mMnlkTAxB20jiF@dpg-d63n4cer433s73d459eg-a/tweakr_db",
  ssl: {
    rejectUnauthorized: false
  }
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('Error acquiring client', err.stack);
  } else {
    console.log('Connected to PostgreSQL database');
    release();
  }
});

async function initDB() {
  try {
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

      CREATE INDEX IF NOT EXISTS idx_licenses_session_id ON licenses(session_id);
      CREATE INDEX IF NOT EXISTS idx_licenses_license_key ON licenses(license_key);
      CREATE INDEX IF NOT EXISTS idx_licenses_hwid ON licenses(hwid);
    `);
    console.log("PostgreSQL database tables ready");
  } catch (err) {
    console.error("Database initialization error:", err);
  }
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

// -------------------- CORS --------------------
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// -------------------- STRIPE WEBHOOK (RAW BODY ONLY) --------------------
app.post(
  "/webhook/stripe",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];

    if (!sig || !STRIPE_WEBHOOK_SECRET) {
      return res.status(400).send("Missing stripe-signature or webhook secret");
    }

    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error("Webhook signature verify failed:", err.message);
      return res.status(400).send("Bad signature");
    }

    try {
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;

        const sessionId = session.id;
        const email =
          (session.customer_details && session.customer_details.email) ||
          session.customer_email ||
          null;

        const amountTotal = session.amount_total || null;
        const currency = session.currency || null;

        // Idempotency: if it exists, do nothing
        const existing = await pool.query(
          "SELECT license_key FROM licenses WHERE session_id = $1",
          [sessionId]
        );

        if (existing.rows.length === 0) {
          const licenseKey = generateLicenseKey();

          await pool.query(
            `INSERT INTO licenses (license_key, session_id, customer_email, amount_total, currency)
             VALUES ($1, $2, $3, $4, $5)`,
            [licenseKey, sessionId, email, amountTotal, currency]
          );

          console.log("License created:", licenseKey, "session:", sessionId, "email:", email);
        } else {
          console.log("Duplicate webhook, session already stored:", sessionId);
        }
      }

      return res.status(200).json({ received: true });
    } catch (err) {
      console.error("Webhook handler error:", err);
      return res.status(500).send("Webhook handler failed");
    }
  }
);

// -------------------- JSON FOR NORMAL ROUTES --------------------
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// -------------------- ROUTES --------------------
app.get("/", (req, res) => {
  res.type("html").send(`
    <html>
      <head><title>Tweakr License Server</title></head>
      <body style="font-family:Arial;padding:32px;">
        <h2>Tweakr License Server</h2>
        <p>Status: ONLINE</p>
        <p>Mode: ${isTestMode ? "TEST" : "LIVE"}</p>
        <p>Database: PostgreSQL</p>
        <p><a href="/health">/health</a></p>
      </body>
    </html>
  `);
});

app.get("/health", async (req, res) => {
  try {
    // Test database connection
    await pool.query("SELECT 1");
    res.json({
      status: "ok",
      mode: isTestMode ? "test" : "live",
      db: "postgresql",
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({
      status: "error",
      db: "postgresql",
      error: err.message,
      timestamp: new Date().toISOString(),
    });
  }
});

app.post("/api/create-checkout", async (req, res) => {
  try {
    const price = 30;

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: isTestMode
                ? "Tweakr Pro - TEST ($0.50)"
                : "Tweakr Pro - Lifetime License",
              description: "HWID-locked FPS optimization tool for Windows 10/11",
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

    res.json({
      success: true,
      url: session.url,
      sessionId: session.id,
      amount: price / 100,
      mode: isTestMode ? "test" : "live",
    });
  } catch (err) {
    console.error("create-checkout error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get("/api/license/:sessionId", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT license_key, created_at FROM licenses WHERE session_id = $1",
      [req.params.sessionId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "License not found",
      });
    }

    res.json({
      success: true,
      license_key: result.rows[0].license_key,
      created_at: result.rows[0].created_at,
    });
  } catch (err) {
    console.error("get-license error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

app.post("/api/activate", async (req, res) => {
  try {
    const license_key = req.body.license_key;
    const hwid = req.body.hwid;

    if (!license_key || !hwid) {
      return res.json({ success: false, error: "Missing license_key or hwid" });
    }

    const result = await pool.query("SELECT * FROM licenses WHERE license_key = $1", [
      license_key,
    ]);

    if (result.rows.length === 0) {
      return res.json({ success: false, error: "Invalid license key" });
    }

    const row = result.rows[0];

    if (row.activated && row.hwid !== hwid) {
      return res.json({
        success: false,
        error: "License already activated on another computer",
      });
    }

    if (!row.activated) {
      await pool.query(
        "UPDATE licenses SET hwid = $1, activated = true WHERE license_key = $2",
        [hwid, license_key]
      );
    }

    res.json({ success: true, message: "Activated", expires: "Lifetime" });
  } catch (err) {
    console.error("activate error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

app.get("/api/admin/licenses", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT license_key, session_id, customer_email, amount_total, currency, activated, hwid, created_at
       FROM licenses
       ORDER BY id DESC
       LIMIT 100`
    );
    res.json({ count: result.rows.length, licenses: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------- START --------------------
initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log("Server up on port:", PORT);
      console.log("Mode:", isTestMode ? "TEST" : "LIVE");
      console.log("Database: PostgreSQL");
    });
  })
  .catch((err) => {
    console.error("Startup failed:", err);
    process.exit(1);
  });
