const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const rateLimit = require('express-rate-limit');
const Stripe = require('stripe');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // For static files

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use('/api/', limiter);

// Initialize Stripe
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Database setup
let db;
async function initDB() {
    db = await open({
        filename: process.env.DATABASE_URL || './licenses.db',
        driver: sqlite3.Database
    });
    
    // Create tables
    await db.exec(`
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            session_id TEXT UNIQUE,
            customer_email TEXT,
            customer_name TEXT,
            hwid TEXT,
            activated INTEGER DEFAULT 0,
            activated_at DATETIME,
            price_paid INTEGER DEFAULT 1499,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active'
        );
        
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            license_key TEXT,
            customer_email TEXT,
            amount INTEGER,
            status TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_license_key ON licenses(license_key);
        CREATE INDEX IF NOT EXISTS idx_session_id ON licenses(session_id);
    `);
    
    console.log('✅ Database initialized');
}
initDB();

// Generate license key
function generateLicenseKey() {
    const prefix = 'TWEAK';
    const random = crypto.randomBytes(6).toString('hex').toUpperCase();
    const checksum = crypto.createHash('md5').update(random).digest('hex').substring(0, 4).toUpperCase();
    return `${prefix}-${random}-${checksum}`;
}

// ==================== STRIPE CHECKOUT ====================
app.post('/api/create-checkout', async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: 'usd',
                        product_data: {
                            name: 'Tweakr Pro - Lifetime License',
                            description: 'HWID-locked FPS optimization tool for Windows 10/11',
                            images: ['https://tweakr.com/icon.png']
                        },
                        unit_amount: 1499, // $14.99 in cents
                    },
                    quantity: 1,
                }
            ],
            mode: 'payment',
            success_url: `${process.env.BASE_URL || 'https://your-render-url.onrender.com'}/thank-you.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.BASE_URL || 'https://your-render-url.onrender.com'}/cancel.html`,
            metadata: {
                product: 'tweakr-pro',
                version: '2.3.1'
            },
            allow_promotion_codes: true, // Optional: allow discount codes
        });

        console.log(`✅ Checkout session created: ${session.id}`);
        
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

// ==================== STRIPE WEBHOOK ====================
app.post('/webhook/stripe', express.raw({type: 'application/json'}), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
    
    let event;
    
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
        console.log(`✅ Webhook received: ${event.type}`);
    } catch (err) {
        console.error(`❌ Webhook Error: ${err.message}`);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    
    // Handle the event
    switch (event.type) {
        case 'checkout.session.completed':
            const session = event.data.object;
            
            try {
                // Generate license key
                const licenseKey = generateLicenseKey();
                
                // Store in database
                await db.run(
                    `INSERT INTO licenses (license_key, session_id, customer_email, status) 
                     VALUES (?, ?, ?, 'active')`,
                    [licenseKey, session.id, session.customer_details?.email || 'unknown']
                );
                
                await db.run(
                    `INSERT INTO orders (session_id, license_key, customer_email, amount, status) 
                     VALUES (?, ?, ?, ?, 'completed')`,
                    [session.id, licenseKey, session.customer_details?.email || 'unknown', session.amount_total]
                );
                
                console.log(`✅ License created for session ${session.id}: ${licenseKey}`);
                
                // If you want to send email, add your email code here
                
            } catch (dbError) {
                console.error('❌ Database error:', dbError);
            }
            break;
            
        case 'checkout.session.expired':
            console.log(`❌ Session expired: ${event.data.object.id}`);
            break;
            
        default:
            console.log(`ℹ️ Unhandled event type: ${event.type}`);
    }
    
    res.json({received: true});
});

// ==================== GET LICENSE KEY ====================
app.get('/api/get-license/:sessionId', async (req, res) => {
    try {
        const sessionId = req.params.sessionId;
        
        // Get license from database
        const license = await db.get(
            'SELECT license_key, customer_email, created_at FROM licenses WHERE session_id = ?',
            [sessionId]
        );
        
        if (!license) {
            return res.status(404).json({
                success: false,
                error: 'License not found. Payment might still be processing.'
            });
        }
        
        res.json({
            success: true,
            license_key: license.license_key,
            customer_email: license.customer_email,
            created_at: license.created_at,
            instructions: 'Enter this key in Tweakr app to activate your license.'
        });
        
    } catch (error) {
        console.error('❌ Get license error:', error);
        res.status(500).json({
            success: false,
            error: 'Server error'
        });
    }
});

// ==================== LICENSE ACTIVATION (Tweakr App) ====================
app.post('/api/activate', async (req, res) => {
    try {
        const { license_key, hwid } = req.body;
        
        if (!license_key || !hwid) {
            return res.json({
                success: false,
                error: 'Missing license key or HWID'
            });
        }
        
        // Get license from database
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
                `UPDATE licenses 
                 SET hwid = ?, activated = 1, activated_at = CURRENT_TIMESTAMP 
                 WHERE license_key = ?`,
                [hwid, license_key]
            );
            
            console.log(`✅ License activated: ${license_key} for HWID: ${hwid}`);
            
            return res.json({
                success: true,
                message: 'License activated successfully!',
                expires: 'Lifetime',
                features: ['all_optimizations', 'game_profiles', 'premium_support']
            });
        }
        
        // Already activated on same HWID (re-checking)
        if (license.hwid === hwid) {
            return res.json({
                success: true,
                message: 'License validated',
                expires: 'Lifetime'
            });
        }
        
    } catch (error) {
        console.error('❌ Activation error:', error);
        res.status(500).json({
            success: false,
            error: 'Server error'
        });
    }
});

// ==================== LICENSE VALIDATION ====================
app.post('/api/validate', async (req, res) => {
    try {
        const { license_key, hwid } = req.body;
        
        const license = await db.get(
            'SELECT * FROM licenses WHERE license_key = ?',
            [license_key]
        );
        
        if (!license) {
            return res.json({
                valid: false,
                error: 'Invalid license key'
            });
        }
        
        if (license.hwid === hwid && license.activated) {
            return res.json({
                valid: true,
                activated: true,
                email: license.customer_email,
                created_at: license.created_at
            });
        }
        
        return res.json({
            valid: false,
            error: 'License not activated on this computer'
        });
        
    } catch (error) {
        console.error('❌ Validation error:', error);
        res.status(500).json({
            valid: false,
            error: 'Server error'
        });
    }
});

// ==================== ADMIN ENDPOINTS ====================
app.get('/api/admin/licenses', async (req, res) => {
    // Add authentication in production!
    const licenses = await db.all('SELECT license_key, customer_email, activated, created_at FROM licenses ORDER BY id DESC LIMIT 100');
    res.json(licenses);
});

// ==================== HEALTH CHECK ====================
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        service: 'Tweakr License Server',
        timestamp: new Date().toISOString(),
        stripe: process.env.STRIPE_SECRET_KEY ? 'configured' : 'not configured'
    });
});

app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Tweakr License Server</title>
            <style>
                body { font-family: Arial, sans-serif; padding: 40px; }
                .status { color: green; font-weight: bold; }
                code { background: #f5f5f5; padding: 2px 5px; border-radius: 3px; }
            </style>
        </head>
        <body>
            <h1>🎮 Tweakr License Server</h1>
            <p>Status: <span class="status">● Online</span></p>
            <p>Endpoints:</p>
            <ul>
                <li><code>POST /api/create-checkout</code> - Create Stripe checkout</li>
                <li><code>POST /webhook/stripe</code> - Stripe webhook</li>
                <li><code>GET /api/get-license/:sessionId</code> - Get license after payment</li>
                <li><code>POST /api/activate</code> - Activate license (Tweakr app)</li>
                <li><code>POST /api/validate</code> - Validate license</li>
                <li><code>GET /health</code> - Health check</li>
            </ul>
            <p><a href="/thank-you.html?session_id=test" target="_blank">Test Thank You Page</a></p>
        </body>
        </html>
    `);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Tweakr License Server running on port ${PORT}`);
    console.log(`🔗 Base URL: ${process.env.BASE_URL || `http://localhost:${PORT}`}`);
});
