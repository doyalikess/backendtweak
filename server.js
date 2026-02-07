const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const Stripe = require('stripe');

const app = express();

// ==================== FIX 1: CORS ====================
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================== FIX 2: INITIALIZE STRIPE ====================
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_xxxx');

// ==================== FIX 3: DATABASE SETUP ====================
let db;
async function initDB() {
    try {
        db = await open({
            filename: process.env.DATABASE_URL || './licenses.db',
            driver: sqlite3.Database
        });
        
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
        
        console.log('✅ Database initialized successfully');
    } catch (error) {
        console.error('❌ Database error:', error);
    }
}

// Initialize database
initDB();

// ==================== FIX 4: GENERATE LICENSE KEY ====================
function generateLicenseKey() {
    const prefix = 'TWEAK';
    const random = crypto.randomBytes(6).toString('hex').toUpperCase();
    const checksum = crypto.createHash('md5').update(random).digest('hex').substring(0, 4).toUpperCase();
    return `${prefix}-${random}-${checksum}`;
}

// ==================== FIX 5: HEALTH CHECK (MUST COME FIRST) ====================
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        service: 'Tweakr License Server',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// ==================== FIX 6: HOME PAGE ====================
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
            <p><strong>Status: <span style="color:green;">● ONLINE</span></strong></p>
            <p>Server is running and ready to process payments.</p>
            <p><a href="/health">Health Check</a> | <a href="/test">Test Endpoint</a></p>
        </body>
        </html>
    `);
});

// ==================== FIX 7: TEST ENDPOINT ====================
app.get('/test', (req, res) => {
    res.json({
        message: 'Server is working!',
        endpoints: {
            health: 'GET /health',
            createCheckout: 'POST /api/create-checkout',
            getLicense: 'GET /api/license/:sessionId',
            activate: 'POST /api/activate',
            webhook: 'POST /webhook/stripe'
        }
    });
});

// ==================== FIX 8: CREATE CHECKOUT ====================
app.post('/api/create-checkout', async (req, res) => {
    console.log('📦 Creating checkout session...');
    
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{
                price_data: {
                    currency: 'usd',
                    product_data: {
                        name: 'Tweakr Pro - Lifetime License',
                        description: 'HWID-locked FPS optimization tool for Windows 10/11',
                    },
                    unit_amount: 1499, // $0.50
                },
                quantity: 1,
            }],
            mode: 'payment',
            success_url: 'https://tweakr.store/#download?success=true&session_id={CHECKOUT_SESSION_ID}',
            cancel_url: 'https://tweakr.store/#download?canceled=true',
        });

        console.log('✅ Checkout session created:', session.id);
        
        res.json({ 
            success: true, 
            url: session.url,
            sessionId: session.id
        });
        
    } catch (error) {
        console.error('❌ Checkout error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// ==================== FIX 9: WEBHOOK HANDLER ====================
app.post('/webhook/stripe', express.raw({type: 'application/json'}), async (req, res) => {
    console.log('🔔 Webhook received');
    
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_xxxx';
    
    let event;
    
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
        console.log('✅ Webhook verified:', event.type);
    } catch (err) {
        console.error('❌ Webhook verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    
    // Handle checkout.session.completed
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        console.log('💳 Payment completed for session:', session.id);
        
        try {
            const licenseKey = generateLicenseKey();
            
            // Save to database
            if (db) {
                await db.run(
                    `INSERT INTO licenses (license_key, session_id, customer_email) VALUES (?, ?, ?)`,
                    [licenseKey, session.id, session.customer_details?.email || 'unknown']
                );
                console.log('✅ License saved:', licenseKey);
            }
            
        } catch (dbError) {
            console.error('❌ Database save error:', dbError);
        }
    }
    
    res.json({ received: true });
});

// ==================== FIX 10: GET LICENSE ====================
app.get('/api/license/:sessionId', async (req, res) => {
    console.log('🔑 Getting license for session:', req.params.sessionId);
    
    try {
        if (!db) {
            return res.status(500).json({ error: 'Database not initialized' });
        }
        
        const license = await db.get(
            'SELECT license_key FROM licenses WHERE session_id = ?',
            [req.params.sessionId]
        );
        
        if (license) {
            res.json({ 
                success: true, 
                license_key: license.license_key 
            });
        } else {
            res.status(404).json({ 
                success: false, 
                error: 'License not found. Payment might still be processing.' 
            });
        }
    } catch (error) {
        console.error('❌ Get license error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Server error' 
        });
    }
});

// ==================== FIX 11: ACTIVATE LICENSE ====================
app.post('/api/activate', async (req, res) => {
    console.log('🔐 Activating license...');
    
    try {
        const { license_key, hwid } = req.body;
        
        if (!license_key || !hwid) {
            return res.json({ 
                success: false, 
                error: 'Missing license key or HWID' 
            });
        }
        
        if (!db) {
            return res.json({ 
                success: false, 
                error: 'Database not available' 
            });
        }
        
        const license = await db.get(
            'SELECT * FROM licenses WHERE license_key = ?',
            [license_key]
        );
        
        if (!license) {
            return res.json({ 
                success: false, 
                error: 'Invalid license key' 
            });
        }
        
        // Check if already activated on different HWID
        if (license.activated && license.hwid !== hwid) {
            return res.json({ 
                success: false, 
                error: 'License already activated on another computer' 
            });
        }
        
        // First activation
        if (!license.activated) {
            await db.run(
                'UPDATE licenses SET hwid = ?, activated = 1 WHERE license_key = ?',
                [hwid, license_key]
            );
            console.log('✅ License activated:', license_key);
        }
        
        res.json({ 
            success: true, 
            message: 'License activated successfully!',
            expires: 'Lifetime'
        });
        
    } catch (error) {
        console.error('❌ Activation error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Server error' 
        });
    }
});

// ==================== FIX 12: 404 HANDLER ====================
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Endpoint not found',
        availableEndpoints: {
            'GET /': 'Home page',
            'GET /health': 'Health check',
            'GET /test': 'Test endpoint',
            'POST /api/create-checkout': 'Create Stripe checkout',
            'GET /api/license/:sessionId': 'Get license by session ID',
            'POST /api/activate': 'Activate license with HWID',
            'POST /webhook/stripe': 'Stripe webhook'
        }
    });
});

// ==================== FIX 13: ERROR HANDLER ====================
app.use((error, req, res, next) => {
    console.error('🚨 Server error:', error);
    res.status(500).json({ 
        error: 'Internal server error',
        message: error.message 
    });
});

// ==================== FIX 14: START SERVER ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Tweakr License Server running on port ${PORT}`);
    console.log(`🔗 Health check: http://localhost:${PORT}/health`);
    console.log(`🔗 Test endpoint: http://localhost:${PORT}/test`);
});
