// server.js
"use strict";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();
const { open } = require("sqlite");
const Stripe = require("stripe");

const app = express();

// -------------------- CONFIG --------------------
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const DATABASE_PATH = process.env.DATABASE_URL || "./licenses.db";
const PORT = process.env.PORT || 3000;

if (!STRIPE_SECRET_KEY) {
  console.error("Missing STRIPE_SECRET_KEY");
}

const stripe = new Stripe(STRIPE_SECRET_KEY, { apiVersion: "2024-06-20" });
const isTestMode = STRIPE_SECRET_KEY.startsWith("sk_test_");

// -------------------- DB --------------------
let db;

async function initDB() {
  db = await open({
    filename: DATABASE_PATH,
    driver: sqlite3.Database,
  });

  await db.exec(`
    PRAGMA journal_mode = WAL;

    CREATE TABLE IF NOT EXISTS licenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      license_key TEXT UNIQUE NOT NULL,
      session_id TEXT UNIQUE NOT NULL,
      customer_email TEXT,
      amount_total INTEGER,
      currency TEXT,
      hwid TEXT,
      activated INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_licenses_session_id ON licenses(session_id);
    CREATE INDEX IF NOT EXISTS idx_licenses_license_key ON licenses(license_key);
  `);

  console.log("DB ready:", DATABASE_PATH);
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
// Put this route BEFORE express.json()
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
        const existing = await db.get(
          "SELECT license_key FROM licenses WHERE session_id = ?",
          [sessionId]
        );

        if (!existing) {
          const licenseKey = generateLicenseKey();

          await db.run(
            `INSERT INTO licenses (license_key, session_id, customer_email, amount_total, currency)
             VALUES (?, ?, ?, ?, ?)`,
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
        <p><a href="/health">/health</a></p>
      </body>
    </html>
  `);
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    mode: isTestMode ? "test" : "live",
    db: !!db,
    timestamp: new Date().toISOString(),
  });
});

app.post("/api/create-checkout", async (req, res) => {
  try {
    const price = isTestMode ? 50 : 1499;

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
    const row = await db.get(
      "SELECT license_key, created_at FROM licenses WHERE session_id = ?",
      [req.params.sessionId]
    );

    if (!row) {
      return res.status(404).json({
        success: false,
        error: "License not found",
      });
    }

    res.json({
      success: true,
      license_key: row.license_key,
      created_at: row.created_at,
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

    const row = await db.get("SELECT * FROM licenses WHERE license_key = ?", [
      license_key,
    ]);

    if (!row) {
      return res.json({ success: false, error: "Invalid license key" });
    }

    if (row.activated && row.hwid !== hwid) {
      return res.json({
        success: false,
        error: "License already activated on another computer",
      });
    }

    if (!row.activated) {
      await db.run(
        "UPDATE licenses SET hwid = ?, activated = 1 WHERE license_key = ?",
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
    const rows = await db.all(
      `SELECT license_key, session_id, customer_email, amount_total, currency, activated, hwid, created_at
       FROM licenses
       ORDER BY id DESC
       LIMIT 100`
    );
    res.json({ count: rows.length, licenses: rows });
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
    });
  })
  .catch((err) => {
    console.error("Startup failed:", err);
    process.exit(1);
  });
