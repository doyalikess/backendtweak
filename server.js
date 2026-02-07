const express = require('express');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use('/api/', limiter);

// SQLite database setup
let db;
async function initDB() {
    db = await open({
        filename: process.env.DATABASE_URL || './licenses.db',
        driver: sqlite3.Database
    });
    
    await db.exec(`
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE,
            lemon_key TEXT,
            customer_email TEXT,
            order_id TEXT,
            hwid TEXT,
            activated BOOLEAN DEFAULT 0,
            activations INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            activated_at DATETIME,
            ip_address TEXT,
            last_check DATETIME
        )
    `);
    
    console.log('Database initialized');
}
initDB();

// Email setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Generate license key
function generateLicenseKey() {
    const prefix = 'TWEAK';
    const random = crypto.randomBytes(6).toString('hex').toUpperCase();
    const checksum = crypto.createHash('md5').update(random).digest('hex').substring(0, 4).toUpperCase();
    return `${prefix}-${random}-${checksum}`;
}

// Webhook endpoint
app.post('/webhook/lemonsqueezy', async (req, res) => {
    try {
        const signature = req.headers['x-signature'];
        const payload = JSON.stringify(req.body);
        const secret = process.env.LEMON_WEBHOOK_SECRET;
        
        // Verify signature
        const hmac = crypto.createHmac('sha256', secret);
        const digest = hmac.update(payload).digest('hex');
        
        if (signature !== digest) {
            console.error('Invalid webhook signature');
            return res.status(401).send('Invalid signature');
        }
        
        const event = req.body;
        
        // Handle order creation
        if (event.event_name === 'order_created' && event.data.attributes.status === 'paid') {
            const orderId = event.data.id;
            const customerEmail = event.data.attributes.user_email;
            const customerName = event.data.attributes.first_name;
            const lemonLicenseKey = event.data.attributes.identifier;
            
            // Generate Tweakr license
            const tweakrLicense = generateLicenseKey();
            
            // Store in database
            await db.run(
                `INSERT INTO licenses (license_key, lemon_key, customer_email, order_id) 
                 VALUES (?, ?, ?, ?)`,
                [tweakrLicense, lemonLicenseKey, customerEmail, orderId]
            );
            
            // Send email
            await sendLicenseEmail(customerEmail, customerName, tweakrLicense, lemonLicenseKey);
            
            console.log(`License created for ${customerEmail}: ${tweakrLicense}`);
        }
        
        res.status(200).json({ status: 'success' });
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Send license email
async function sendLicenseEmail(email, name, tweakrKey, lemonKey) {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your Tweakr Pro License Key',
        html: `
            <h2>🎮 Welcome to Tweakr Pro!</h2>
            <p>Hi ${name},</p>
            <p>Thank you for purchasing Tweakr Pro! Here are your license details:</p>
            
            <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3>🔑 Your Tweakr License (HWID-Locked):</h3>
                <div style="font-size: 18px; font-family: monospace; background: #333; color: #00ff41; padding: 15px; border-radius: 5px;">
                    ${tweakrKey}
                </div>
                <p><strong>Use this key in the Tweakr application.</strong></p>
            </div>
            
            <div style="background: #e8f4fd; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3>📝 Lemon Squeezy License:</h3>
                <div style="font-family: monospace; background: #fff; padding: 10px; border-radius: 5px;">
                    ${lemonKey}
                </div>
                <p>Use this key for account management on Lemon Squeezy.</p>
            </div>
            
            <h3>📥 How to Activate:</h3>
            <ol>
                <li>Download Tweakr from our website</li>
                <li>Launch the application</li>
                <li>Enter your Tweakr license key when prompted</li>
                <li>The license will automatically bind to your computer (HWID)</li>
            </ol>
            
            <p><strong>⚠️ Important:</strong> This license is HWID-locked to one computer only.</p>
            
            <p>Need help? Contact support at support@tweakr.com</p>
            <p>Happy gaming! 🎯</p>
            <p><em>The Tweakr Team</em></p>
        `
    };
    
    await transporter.sendMail(mailOptions);
}

// API: Activate license
app.post('/api/activate', async (req, res) => {
    try {
        const { license_key, hwid, ip } = req.body;
        
        // Validate input
        if (!license_key || !hwid) {
            return res.status(400).json({ success: false, error: 'Missing license key or HWID' });
        }
        
        // Check if license exists
        const license = await db.get('SELECT * FROM licenses WHERE license_key = ?', [license_key]);
        
        if (!license) {
            return res.json({ success: false, error: 'Invalid license key' });
        }
        
        // Check if already activated
        if (license.activated) {
            // Check if same HWID
            if (license.hwid === hwid) {
                return res.json({ 
                    success: true, 
                    message: 'License already activated on this computer',
                    expires: 'Never'
                });
            } else {
                return res.json({ 
                    success: false, 
                    error: 'License already activated on another computer'
                });
            }
        }
        
        // Activate license
        await db.run(
            `UPDATE licenses SET 
             hwid = ?, 
             activated = 1, 
             activations = 1, 
             activated_at = CURRENT_TIMESTAMP,
             ip_address = ?,
             last_check = CURRENT_TIMESTAMP
             WHERE license_key = ?`,
            [hwid, ip || 'unknown', license_key]
        );
        
        console.log(`License activated: ${license_key} for HWID: ${hwid}`);
        
        res.json({ 
            success: true, 
            message: 'License activated successfully!',
            expires: 'Never',
            features: ['all']
        });
        
    } catch (error) {
        console.error('Activation error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

// API: Validate license (app checks this on startup)
app.post('/api/validate', async (req, res) => {
    try {
        const { license_key, hwid } = req.body;
        
        const license = await db.get('SELECT * FROM licenses WHERE license_key = ?', [license_key]);
        
        if (!license) {
            return res.json({ valid: false, error: 'Invalid license' });
        }
        
        // Update last check time
        await db.run('UPDATE licenses SET last_check = CURRENT_TIMESTAMP WHERE license_key = ?', [license_key]);
        
        if (license.hwid === hwid) {
            return res.json({ 
                valid: true,
                activated: true,
                email: license.customer_email,
                created: license.created_at,
                activations: license.activations
            });
        } else {
            return res.json({ 
                valid: false, 
                error: 'License not activated on this computer'
            });
        }
    } catch (error) {
        console.error('Validation error:', error);
        res.status(500).json({ valid: false, error: 'Server error' });
    }
});

// API: Get license info (for admin dashboard)
app.get('/api/license/:key', async (req, res) => {
    const license = await db.get('SELECT * FROM licenses WHERE license_key = ?', [req.params.key]);
    
    if (!license) {
        return res.status(404).json({ error: 'License not found' });
    }
    
    // Hide sensitive data
    delete license.hwid;
    
    res.json(license);
});

// Health check endpoint (Render needs this)
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        service: 'Tweakr License Server',
        timestamp: new Date().toISOString()
    });
});

app.get('/', (req, res) => {
    res.send(`
        <h1>🎮 Tweakr License Server</h1>
        <p>This server handles license management for Tweakr Pro.</p>
        <p>Endpoints:</p>
        <ul>
            <li><code>POST /webhook/lemonsqueezy</code> - Lemon Squeezy webhook</li>
            <li><code>POST /api/activate</code> - Activate license</li>
            <code>POST /api/validate</code> - Validate license</li>
            <li><code>GET /health</code> - Health check</li>
        </ul>
        <p>Status: <span style="color: green;">● Online</span></p>
    `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Tweakr License Server running on port ${PORT}`);
});
