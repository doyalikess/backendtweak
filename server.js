"use strict";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");
const Stripe = require("stripe");

const app = express();

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const PORT = process.env.PORT || 3000;

const stripe = new Stripe(STRIPE_SECRET_KEY, {
  apiVersion: "2024-06-20",
});

const isTestMode = STRIPE_SECRET_KEY.startsWith("sk_test_");

// ---------------- DATABASE ----------------

const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ||
    "postgresql://tweakr_db_user:3XwJoMz3SQBh7HsQh6mMnlkTAxB20jiF@dpg-d63n4cer433s73d459eg-a/tweakr_db",
  ssl: { rejectUnauthorized: false },
});

pool.connect((err) => {
  if (err) console.error("DB connection error", err.stack);
  else console.log("PostgreSQL connected");
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS licenses(
      id SERIAL PRIMARY KEY,
      license_key VARCHAR(100) UNIQUE NOT NULL,
      session_id VARCHAR(100) UNIQUE,
      customer_email VARCHAR(255),
      amount_total INTEGER,
      currency VARCHAR(10),
      hwid VARCHAR(100),
      activated BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_license_key ON licenses(license_key);
    CREATE INDEX IF NOT EXISTS idx_session ON licenses(session_id);
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

app.use(cors({
  origin: "*",
  methods: ["GET","POST","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"]
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// ---------------- STRIPE WEBHOOK ----------------

app.post(
  "/webhook/stripe",
  express.raw({ type: "application/json" }),
  async (req, res) => {

    const sig = req.headers["stripe-signature"];

    if (!sig || !STRIPE_WEBHOOK_SECRET) {
      return res.status(400).send("Missing signature");
    }

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

    try {
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;

        const sessionId = session.id;
        const email =
          session.customer_details?.email ||
          session.customer_email ||
          null;

        const amountTotal = session.amount_total;
        const currency = session.currency;

        const exists = await pool.query(
          "SELECT id FROM licenses WHERE session_id=$1",
          [sessionId]
        );

        if (exists.rows.length === 0) {
          const licenseKey = generateLicenseKey();

          await pool.query(
            `INSERT INTO licenses
            (license_key, session_id, customer_email, amount_total, currency)
            VALUES($1,$2,$3,$4,$5)`,
            [licenseKey, sessionId, email, amountTotal, currency]
          );

          console.log("License generated:", licenseKey);
        }
      }

      res.json({ received: true });

    } catch (err) {
      console.error(err);
      res.status(500).send("Webhook error");
    }
  }
);

// ---------------- ROUTES ----------------

app.get("/", (req, res) => {
  res.send(`
  <h2>Tweakr License Server</h2>
  <p>Status: ONLINE</p>
  <p>Mode: ${isTestMode ? "TEST" : "LIVE"}</p>
  <a href="/admin.html">Admin Panel</a>
  `);
});

app.get("/health", async (req,res)=>{
  try{
    await pool.query("SELECT 1");
    res.json({
      status:"ok",
      mode:isTestMode?"test":"live",
      timestamp:new Date().toISOString()
    });
  }catch(err){
    res.status(500).json({status:"error",error:err.message});
  }
});

// ---------------- LICENSE API ----------------

app.get("/api/licenses", async (req,res)=>{
  try{
    const result = await pool.query(
      "SELECT * FROM licenses ORDER BY id DESC LIMIT 200"
    );

    res.json({
      success:true,
      count:result.rows.length,
      licenses:result.rows
    });

  }catch(err){
    res.status(500).json({success:false,error:err.message});
  }
});

app.post("/api/licenses/add", async (req,res)=>{
  try{
    const { license_key, customer_email, hwid } = req.body;

    if(!license_key){
      return res.json({success:false,error:"Missing license_key"});
    }

    await pool.query(
      `INSERT INTO licenses
      (license_key,customer_email,hwid,activated)
      VALUES($1,$2,$3,$4)`,
      [license_key, customer_email||null, hwid||null, !!hwid]
    );

    res.json({success:true});

  }catch(err){
    res.status(500).json({success:false,error:err.message});
  }
});

app.delete("/api/licenses/delete/:id", async (req,res)=>{
  try{

    const result = await pool.query(
      "DELETE FROM licenses WHERE id=$1",
      [req.params.id]
    );

    if(result.rowCount===0){
      return res.json({success:false,error:"Not found"});
    }

    res.json({success:true});

  }catch(err){
    res.status(500).json({success:false,error:err.message});
  }
});

app.post("/api/licenses/reset/:id", async (req,res)=>{
  try{

    await pool.query(
      "UPDATE licenses SET hwid=NULL, activated=false WHERE id=$1",
      [req.params.id]
    );

    res.json({success:true});

  }catch(err){
    res.status(500).json({success:false,error:err.message});
  }
});

app.get("/api/license/:sessionId", async (req,res)=>{
  try{
    const result = await pool.query(
      "SELECT license_key,created_at FROM licenses WHERE session_id=$1",
      [req.params.sessionId]
    );

    if(result.rows.length===0){
      return res.status(404).json({success:false,error:"Not found"});
    }

    res.json({
      success:true,
      license_key:result.rows[0].license_key,
      created_at:result.rows[0].created_at
    });

  }catch(err){
    res.status(500).json({success:false,error:"Server error"});
  }
});

app.post("/api/activate", async (req,res)=>{
  try{

    const { license_key, hwid } = req.body;

    if(!license_key || !hwid){
      return res.json({success:false,error:"Missing fields"});
    }

    const result = await pool.query(
      "SELECT * FROM licenses WHERE license_key=$1",
      [license_key]
    );

    if(result.rows.length===0){
      return res.json({success:false,error:"Invalid license"});
    }

    const row = result.rows[0];

    if(row.activated && row.hwid !== hwid){
      return res.json({
        success:false,
        error:"License locked to another PC"
      });
    }

    if(!row.activated){
      await pool.query(
        "UPDATE licenses SET hwid=$1, activated=true WHERE license_key=$2",
        [hwid,license_key]
      );
    }

    res.json({success:true,message:"Activated"});

  }catch(err){
    res.status(500).json({success:false,error:"Server error"});
  }
});

// ---------------- START ----------------

initDB().then(()=>{
  app.listen(PORT,()=>{
    console.log("Server running on port",PORT);
    console.log("Mode:",isTestMode?"TEST":"LIVE");
  });
}).catch(err=>{
  console.error(err);
  process.exit(1);
});
