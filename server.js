const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const Stripe = require('stripe');

const app = express();

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================== STRIPE ====================
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_xxxx');
const isTestMode = process.env.STRIPE_SECRET_KEY?.startsWith('sk_test_');

// ==================== DATABASE - SIMPLE FIX ====================
let db;

async function initDB() {
    try {
        // Use Render's persistent disk path
        db = await open({
            filename: '/opt/render/project/src/licenses.db',
            driver: sqlite3.Database
        });
        
        // Create table if not exists
        await db.exec(`
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT UNIQUE NOT NULL,
                session_id TEXT UNIQUE,
                customer_email TEXT,
                hwid TEXT,
                activated INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        console.log('✅ Database connected at:', '/opt/render/project/src/licenses.db');
    } catch (error) {
        console.error('❌ Database error:', error);
        // Fallback to in-memory
        db = await open({
            filename: ':memory:',
            driver: sqlite3.Database
        });
        await db.exec(`
            CREATE TABLE licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT UNIQUE NOT NULL,
                session_id TEXT UNIQUE,
                customer_email TEXT,
                hwid TEXT,
                activated INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('⚠️ Using in-memory database (licenses will be lost on restart)');
    }
}

// Initialize database
initDB();

// ==================== GENERATE LICENSE ====================
function generateLicenseKey() {
    const prefix = 'TWEAK';
    const random = crypto.randomBytes(6).toString('hex').toUpperCase();
    const checksum = crypto.createHash('md5').update(random).digest('hex').substring(0, 4).toUpperCase();
    return `${prefix}-${random}-${checksum}`;
}

// ==================== HEALTH CHECK ====================
app.get('/health', async (req, res) => {
    const dbStatus = db ? 'connected' : 'disconnected';
    let licenseCount = 0;
    
    if (db) {
        try {
            const result = await db.get('SELECT COUNT(*) as count FROM licenses');
            licenseCount = result.count;
        } catch (e) {
            console.error('Count error:', e);
        }
    }
    
    res.json({ 
        status: 'ok', 
        mode: isTestMode ? 'test' : 'live',
        database: dbStatus,
        licenses: licenseCount,
        timestamp: new Date().toISOString()
    });
});

// ==================== CREATE CHECKOUT ====================
app.post('/api/create-checkout', async (req, res) => {
    console.log('📦 Creating checkout...');
    
    try {
        const price = isTestMode ? 50 : 1499; // $0.50 test, $14.99 live
        
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{
                price_data: {
                    currency: 'usd',
                    product_data: {
                        name: isTestMode ? 'Tweakr Pro - TEST ($0.50)' : 'Tweakr Pro - Lifetime License',
                        description: 'HWID-locked FPS optimization tool',
                    },
                    unit_amount: price,
                },
                quantity: 1,
            }],
            mode: 'payment',
            success_url: 'https://tweakr.store/#download?success=true&session_id={CHECKOUT_SESSION_ID}&t=' + Date.now(),
            cancel_url: 'https://tweakr.store/#download?canceled=true',
        });

        console.log(`✅ Checkout created: ${session.id}`);
        
        res.json({ 
            success: true, 
            url: session.url,
            sessionId: session.id
        });
        
    } catch (error) {
        console.error('❌ Checkout error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==================== FIXED WEBHOOK ====================
app.post('/webhook/stripe', 
    // RAW body middleware
    express.raw({type: 'application/json'}),
    
    async (req, res) => {
        console.log('🔔 Webhook received');
        
        const sig = req.headers['stripe-signature'];
        const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
        
        if (!sig || !webhookSecret) {
            console.error('❌ Missing signature or secret');
            return res.status(400).json({ error: 'Missing signature or secret' });
        }
        
        let event;
        
        try {
            // Verify with raw body
            event = stripe.webhooks.constructEvent(
                req.body,  // Raw buffer
                sig,
                webhookSecret
            );
            
            console.log(`✅ Webhook verified: ${event.type}`);
            
        } catch (err) {
            console.error('❌ Webhook verification failed:', err.message);
            return res.status(400).json({ error: err.message });
        }
        
        // Respond immediately
        res.json({ received: true, status: 'processing' });
        
        // Process in background
        if (event.type === 'checkout.session.completed') {
            const session = event.data.object;
            console.log(`💰 Payment completed: ${session.id}`);
            
            // Generate license
            const licenseKey = generateLicenseKey();
            console.log(`🎫 License: ${licenseKey}`);
            
            // Save to database (with error handling)
            if (db) {
                try {
                    await db.run(
                        `INSERT INTO licenses (license_key, session_id, customer_email) VALUES (?, ?, ?)`,
                        [licenseKey, session.id, session.customer_details?.email || 'unknown@test.com']
                    );
                    console.log(`💾 Saved to database: ${licenseKey}`);
                    
                    // Verify it was saved
                    const saved = await db.get(
                        'SELECT license_key FROM licenses WHERE session_id = ?',
                        [session.id]
                    );
                    
                    if (saved) {
                        console.log(`✅ Verified saved: ${saved.license_key}`);
                    } else {
                        console.error('❌ License not found after save!');
                    }
                    
                } catch (dbError) {
                    console.error('❌ Database save error:', dbError.message);
                    console.error('Full error:', dbError);
                }
            } else {
                console.error('❌ Database not available');
            }
        }
    }
);

// ==================== GET LICENSE ====================
app.get('/api/license/:sessionId', async (req, res) => {
    console.log(`🔍 Looking for license: ${req.params.sessionId}`);
    
    try {
        if (!db) {
            return res.status(500).json({ error: 'Database not available' });
        }
        
        const license = await db.get(
            'SELECT license_key, created_at FROM licenses WHERE session_id = ?',
            [req.params.sessionId]
        );
        
        console.log('License query result:', license);
        
        if (license) {
            res.json({ 
                success: true, 
                license_key: license.license_key,
                created_at: license.created_at
            });
        } else {
            // Check if ANY licenses exist
            const allLicenses = await db.all('SELECT session_id FROM licenses LIMIT 5');
            console.log('All licenses in DB:', allLicenses);
            
            res.status(404).json({ 
                success: false, 
                error: 'License not found',
                note: 'Check webhook logs. Payment might still be processing.',
                total_licenses: allLicenses.length
            });
        }
    } catch (error) {
        console.error('License query error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==================== VIEW ALL LICENSES ====================
app.get('/api/admin/licenses', async (req, res) => {
    try {
        if (!db) {
            return res.json({ error: 'Database not available' });
        }
        
        const licenses = await db.all(`
            SELECT license_key, session_id, customer_email, 
                   created_at, activated 
            FROM licenses 
            ORDER BY id DESC
        `);
        
        res.json({ 
            count: licenses.length,
            licenses: licenses 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== MANUAL LICENSE CREATION (FOR TESTING) ====================
app.post('/api/create-license-manually', async (req, res) => {
    const { session_id, email } = req.body;
    
    const licenseKey = generateLicenseKey();
    
    console.log(`🎫 Manually creating license: ${licenseKey}`);
    
    if (db) {
        try {
            await db.run(
                `INSERT INTO licenses (license_key, session_id, customer_email) VALUES (?, ?, ?)`,
                [licenseKey, session_id || 'manual_' + Date.now(), email || 'manual@test.com']
            );
            
            res.json({ 
                success: true, 
                license_key: licenseKey,
                message: 'License created manually'
            });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    } else {
        res.status(500).json({ error: 'Database not available' });
    }
});

// ==================== ACTIVATE LICENSE ====================
app.post('/api/activate', async (req, res) => {
    const { license_key, hwid } = req.body;
    
    if (!license_key || !hwid) {
        return res.json({ success: false, error: 'Missing license or HWID' });
    }
    
    try {
        const license = await db.get(
            'SELECT * FROM licenses WHERE license_key = ?',
            [license_key]
        );
        
        if (!license) {
            return res.json({ success: false, error: 'Invalid license' });
        }
        
        if (license.activated && license.hwid !== hwid) {
            return res.json({ success: false, error: 'Already activated on another PC' });
        }
        
        if (!license.activated) {
            await db.run(
                'UPDATE licenses SET hwid = ?, activated = 1 WHERE license_key = ?',
                [hwid, license_key]
            );
        }
        
        res.json({ success: true, message: 'License activated' });
        
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== HOME PAGE ====================
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Tweakr License Server</title>
            <style>body{font-family:Arial;padding:40px;text-align:center;}</style>
        </head>
        <body>
            <h1>🎮 Tweakr License Server</h1>
            <p>Status: <strong style="color:green">ONLINE</strong></p>
            <p>Mode: <strong>${isTestMode ? 'TEST' : 'LIVE'}</strong></p>
            <p><a href="/health">Health Check</a> | <a href="/api/admin/licenses">View Licenses</a></p>
            <p><a href="/api/create-license-manually" target="_blank">Create Test License (Manual)</a></p>
        </body>
        </html>
    `);
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔗 Mode: ${isTestMode ? 'TEST' : 'LIVE'}`);
    console.log(`🔗 Health: http://localhost:${PORT}/health`);
});
