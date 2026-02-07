const express = require('express');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const Stripe = require('stripe');

const app = express();
app.use(express.json());

// Initialize Stripe
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Database setup
let db;
async function initDB() {
    db = await open({
        filename: '/opt/render/project/src/licenses.db',
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
    console.log('✅ Database ready');
}
initDB();

// Generate license key
function generateLicenseKey() {
    const prefix = 'TWEAK';
    const random = crypto.randomBytes(6).toString('hex').toUpperCase();
    const checksum = crypto.createHash('md5').update(random).digest('hex').substring(0, 4).toUpperCase();
    return `${prefix}-${random}-${checksum}`;
}

// ==================== CREATE CHECKOUT ====================
app.post('/api/create-checkout', async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{
                price_data: {
                    currency: 'usd',
                    product_data: {
                        name: 'Tweakr Pro - Lifetime License',
                        description: 'HWID-locked FPS optimization tool for Windows',
                    },
                    unit_amount: 1499,
                },
                quantity: 1,
            }],
            mode: 'payment',
            success_url: `https://${req.get('host')}/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `https://${req.get('host')}/cancel`,
        });

        res.json({ url: session.url });
    } catch (error) {
        console.error('Checkout error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==================== STRIPE WEBHOOK ====================
app.post('/webhook/stripe', express.raw({type: 'application/json'}), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    
    try {
        const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
        
        if (event.type === 'checkout.session.completed') {
            const session = event.data.object;
            const licenseKey = generateLicenseKey();
            
            await db.run(
                `INSERT INTO licenses (license_key, session_id, customer_email) VALUES (?, ?, ?)`,
                [licenseKey, session.id, session.customer_details?.email || 'unknown']
            );
            
            console.log(`✅ License created: ${licenseKey} for ${session.id}`);
        }
        
        res.json({received: true});
    } catch (err) {
        console.error('❌ Webhook error:', err.message);
        res.status(400).send(`Webhook Error: ${err.message}`);
    }
});

// ==================== GET LICENSE ====================
app.get('/api/license/:sessionId', async (req, res) => {
    try {
        const license = await db.get(
            'SELECT license_key FROM licenses WHERE session_id = ?',
            [req.params.sessionId]
        );
        
        if (license) {
            res.json({ license_key: license.license_key });
        } else {
            res.status(404).json({ error: 'License not found' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== ACTIVATE LICENSE ====================
app.post('/api/activate', async (req, res) => {
    try {
        const { license_key, hwid } = req.body;
        
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

// ==================== SIMPLE PAGES ====================
app.get('/success', (req, res) => {
    const sessionId = req.query.session_id;
    res.send(`
        <html>
        <body style="font-family: Arial; padding: 40px; text-align: center;">
            <h1>✅ Payment Successful!</h1>
            <p>Your Tweakr Pro license has been generated.</p>
            <div id="license" style="margin: 20px; padding: 20px; background: #f5f5f5; border-radius: 10px;">
                <p>Loading your license key...</p>
            </div>
            <script>
                fetch('/api/license/${sessionId}')
                    .then(r => r.json())
                    .then(data => {
                        document.getElementById('license').innerHTML = 
                            '<strong>Your License Key:</strong><br>' +
                            '<code style="font-size: 24px; color: green;">' + data.license_key + '</code>' +
                            '<p>Copy this key and enter it in Tweakr app.</p>';
                    });
            </script>
        </body>
        </html>
    `);
});

app.get('/cancel', (req, res) => {
    res.send('<h1>Payment Cancelled</h1><p>No charges were made.</p>');
});

app.get('/', (req, res) => {
    res.send('<h1>Tweakr License Server</h1><p>API is running.</p>');
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
