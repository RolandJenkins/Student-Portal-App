require('dotenv').config();

const express = require('express');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const fs = require('fs');
const http = require('http');
const https = require('https');

const { encrypt, decrypt } = require('./utils/encryption');
const saltRounds = 10;

const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));


const app = express();


// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to SQLite
const db = new sqlite3.Database('./database/student_portal_backup.db', (err) => {
    if (err) {
        console.error('❌ Error opening database:', err.message);
    } else {
        console.log('✅ Connected to SQLite database.');
        db.serialize(() => {
            db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_students_bluegold ON students(bluegold_id)`);
            db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_students_username ON students(username)`);
            db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_login_username ON login(username)`);
        });
    }
});

// Activity Log Setup
db.run(`
  CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    role TEXT,
    activity TEXT NOT NULL,
    ts TEXT NOT NULL
  )
`);

function logEvent({ username = null, role = null, activity }) {
    const ts = new Date().toISOString();
    db.run(
        `INSERT INTO activity_log (username, role, activity, ts) VALUES (?, ?, ?, ?)`,
        [username, role, activity, ts],
        (err) => {
            if (err) console.error('logEvent error:', err.message);
        }
    );
}


// --------------------------------------
// RATE LIMITER & LOGIN
// --------------------------------------
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: { message: "Too many login attempts. Please try again after 15 minutes" },
    standardHeaders: true,
    legacyHeaders: false,
});

app.post('/api/login', loginLimiter, async (req, res) => {
    const { username, password, userType, 'g-recaptcha-response': captchaToken } = req.body;

    if (!username || !password || !userType || !captchaToken) {
        return res.status(400).json({ message: 'Missing credentials or CAPTCHA' });
    }

    // Verify reCAPTCHA
    const secretKey = process.env.RECAPTCHA_SECRET;
    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captchaToken}`;

    try {
        const captchaResp = await fetch(verifyUrl, { method: 'POST' });
        const captchaData = await captchaResp.json();
        if (!captchaData.success) return res.status(403).json({ message: 'CAPTCHA failed' });
    } catch (err) {
        return res.status(500).json({ message: 'CAPTCHA error' });
    }

    // 🔑 Encrypt username DETERMINISTICALLY for lookup
    const encryptedUsername = encrypt(username, true);

    console.log("DEBUG: Plaintext input received:", username);
    console.log("DEBUG: Calculated Hex for DB lookup:", encryptedUsername);

    const sql = `
        SELECT l.id, l.username, l.role, l.password_hash, s.bluegold_id
        FROM login l
        LEFT JOIN students s ON s.username = l.username
        WHERE l.username = ? AND l.role = ?
    `
    ;

    db.get(sql, [encryptedUsername, userType], async (err, row) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (!row || !row.password_hash) return res.status(401).json({ message: 'Invalid credentials' });

        const match = await bcrypt.compare(password, row.password_hash);
        if (!match) return res.status(401).json({ message: 'Invalid credentials' });

        // 🔑 Decrypt username for the frontend/session
        const decryptedUser = decrypt(row.username, true);
        logEvent({ username: decryptedUser, role: row.role, activity: 'Logged in' });

        res.json({ id: row.id, username: decryptedUser, role: row.role, bluegold_id: row.bluegold_id });
    });
});

// --------------------------------------
// STUDENT ROUTES
// --------------------------------------

app.post('/api/students', async (req, res) => {
    const { full_name, bluegold_id, address, phone, email, username, password, actorUsername, actorRole } = req.body || {};

    if (!full_name || !bluegold_id || !username || !password) {
        return res.status(400).json({ message: 'Required fields missing' });
    }

    const phoneDigits = String(phone || '').replace(/\D/g, '');
    const emailLower = email ? String(email).toLowerCase() : null;

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const encryptedUsername = encrypt(username, true); // Deterministic
        const secureAddress = encrypt(address);           // Randomized
        const securePhone = encrypt(phoneDigits);         // Randomized

        const checkSql = `
            SELECT 
                (SELECT COUNT(*) FROM students WHERE bluegold_id = ?) AS b_exists,
                (SELECT COUNT(*) FROM login WHERE username = ?) AS u_exists
        `;

        db.get(checkSql, [bluegold_id, encryptedUsername], (err, row) => {
            if (row.b_exists > 0 || row.u_exists > 0) return res.status(409).json({ message: 'Duplicate ID or Username' });

            db.serialize(() => {
                db.run('BEGIN');
                db.run(`INSERT INTO login (username, password_hash, role) VALUES (?, ?, 'student')`, [encryptedUsername, hashedPassword]);
                db.run(`INSERT INTO students (full_name, bluegold_id, address, phone, email, gpa, total_credits, account_balance, username) VALUES (?, ?, ?, ?, ?, NULL, 0, 0, ?)`, 
                    [full_name, bluegold_id, secureAddress, securePhone, emailLower, encryptedUsername]);
                db.run('COMMIT', (err) => {
                    if (err) return res.status(500).json({ message: 'Commit failed' });
                    logEvent({ username: actorUsername, role: actorRole, activity: `Added student ${bluegold_id}` });
                    res.status(201).json({ full_name, bluegold_id, username });
                });
            });
        });
    } catch (e) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/students', (req, res) => {
    db.all(`SELECT id, full_name, bluegold_id, address, phone, email, gpa, total_credits, account_balance, username FROM students ORDER BY bluegold_id`, [], (err, rows) => {
        if (err) return res.status(500).json({ message: 'DB Error' });
        res.json(rows);
    });
});

app.get('/api/student', (req, res) => {
    const { username, bluegold } = req.query;
    let sql = username ? `SELECT * FROM students WHERE username = ?` : `SELECT * FROM students WHERE bluegold_id = ?`;
    let param = username ? encrypt(username, true) : bluegold;

    db.get(sql, [param], (err, row) => {
        if (!row) return res.status(404).json({ message: 'Not found' });
        if (row.address) row.address = decrypt(row.address);
        if (row.phone) row.phone = decrypt(row.phone);
        if (row.username) row.username = decrypt(row.username, true);
        res.json(row);
    });
});

// --------------------------------------
// UPDATE STUDENT PROFILE (from studentinfo.html)
// --------------------------------------
app.put('/api/student/:bluegold', (req, res) => {
    const keyBlue = req.params.bluegold; // Original BlueGold ID from URL
    const { full_name, address, phone, actorUsername, actorRole } = req.body;

    if (!full_name || !phone) {
        return res.status(400).json({ message: 'Full name and phone are required.' });
    }

    // Phone validation: exactly 10 digits
    const phoneDigits = String(phone).replace(/\D/g, '');
    if (phoneDigits.length !== 10) {
        return res.status(400).json({ message: 'Phone must be exactly 10 digits.' });
    }

    // 🔒 Encrypt the sensitive fields before saving
    // We use standard randomized encryption for PII
    const secureAddress = encrypt(address);
    const securePhone = encrypt(phoneDigits);

    const sql = `
        UPDATE students
           SET full_name = ?,
               address   = ?,
               phone     = ?
         WHERE bluegold_id = ?
    `;

    db.run(sql, [full_name, secureAddress, securePhone, keyBlue], function (err) {
        if (err) {
            console.error('Update Error:', err.message);
            return res.status(500).json({ message: 'Database error occurred.' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ message: 'Student record not found.' });
        }

        // ✅ Log the activity
        // Note: we use actorUsername (which is decrypted by the frontend before sending)
        logEvent({
            username: actorUsername || null,
            role: actorRole || 'student',
            activity: `Student ${keyBlue} updated their profile (Name/Address/Phone).`
        });

        res.json({ message: 'Profile updated successfully!' });
    });
});

// --------------------------------------
// PASSWORD CHANGE
// --------------------------------------
app.post('/api/change-password', async (req, res) => {
    const { username, role, currentPassword, newPassword } = req.body || {};
    const encUser = encrypt(username, true);

    db.get(`SELECT password_hash FROM login WHERE username = ? AND role = ?`, [encUser, role], async (err, row) => {
        if (!row || !(await bcrypt.compare(currentPassword, row.password_hash))) {
            return res.status(401).json({ message: 'Current password incorrect' });
        }
        const newHash = await bcrypt.hash(newPassword, saltRounds);
        db.run(`UPDATE login SET password_hash = ? WHERE username = ? AND role = ?`, [newHash, encUser, role], () => {
            logEvent({ username, role, activity: 'Changed password' });
            res.json({ message: 'Updated' });
        });
    });
});

// --------------------------------------
// HELPERS (GPA, Credits, Activity, HTTPS)
// --------------------------------------

// GPA Update
app.put('/api/students/:bluegold/gpa', (req, res) => {
    const { bluegold } = req.params;
    const { gpa, actorUsername, actorRole } = req.body;
    db.run(`UPDATE students SET gpa = ? WHERE bluegold_id = ?`, [gpa, bluegold], () => {
        logEvent({ username: actorUsername, role: actorRole, activity: `Updated GPA for ${bluegold}` });
        res.json({ message: 'Updated' });
    });
});
// --------------------------------------
// FACULTY ACTION: UPDATE TOTAL CREDITS
// --------------------------------------
app.put('/api/students/:bluegold/credits', (req, res) => {
    const { bluegold } = req.params;
    const { total_credits, actorUsername, actorRole } = req.body;
    const credits = Number(total_credits);

    // 1. Validation: Ensure it's a valid number and role
    if (!Number.isInteger(credits) || credits < 0) {
        return res.status(400).json({ message: 'Total credits must be a non-negative integer' });
    }
    
    if (actorRole !== 'faculty') {
        return res.status(403).json({ message: 'Unauthorized action.' });
    }

    const sql = `UPDATE students SET total_credits = ? WHERE bluegold_id = ?`;

    db.run(sql, [credits, bluegold], function (err) {
        if (err) {
            console.error('Credits Update Error:', err.message);
            return res.status(500).json({ message: 'Database error' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ message: 'Student not found' });
        }

        // 2. Log activity
        logEvent({
            username: actorUsername || null,
            role: actorRole || null,
            activity: `Updated total credits for ${bluegold} to ${credits}`
        });

        res.json({ message: 'Credits updated successfully', total_credits: credits });
    });
});

// --------------------------------------
// FACULTY ACTION: CHARGE/UPDATE BALANCE
// --------------------------------------
app.post('/api/students/:bluegold/charge', (req, res) => {
    const { bluegold } = req.params;
    const { amount, actorUsername, actorRole } = req.body;
    
    if (actorRole !== 'faculty') {
        return res.status(403).json({ message: 'Unauthorized' });
    }

    const sql = `UPDATE students SET account_balance = ? WHERE bluegold_id = ?`;

    db.run(sql, [amount, bluegold], function (err) {
        if (err) {
            console.error('Balance Error:', err.message);
            return res.status(500).json({ message: 'Database error' });
        }
        
        logEvent({
            username: actorUsername,
            role: actorRole,
            activity: `Updated balance for ${bluegold} to ${amount}`
        });

        res.json({ message: 'Balance updated' });
    });
});

app.get('/api/activity/all', (req, res) => {
    db.all(`SELECT * FROM activity_log ORDER BY ts DESC LIMIT 25`, [], (err, rows) => res.json(rows));
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'html', 'home.html')));

const SSL_KEY_PATH  = path.join(__dirname, 'certs', 'localhost-key.pem');
const SSL_CERT_PATH = path.join(__dirname, 'certs', 'localhost.pem');

// Serve home.html as the main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'html', 'home.html'));
});
// Function to start dev HTTPS server
function startHttpsServerDev() {
  let key, cert;
  try {
    key  = fs.readFileSync(SSL_KEY_PATH, 'utf8');
    cert = fs.readFileSync(SSL_CERT_PATH, 'utf8');
  } catch (err) {
    console.error('🔐 Could not read SSL key/cert. Did you create them?', err.message);
    process.exit(1);
  }

  const options = { key, cert };
  const HTTPS_PORT = 3443;
  const HTTP_PORT  = 3080;

  // HTTPS server (your Express app)
  const httpsServer = https.createServer(options, app);
  httpsServer.listen(HTTPS_PORT, () => {
    console.log(`🚀 Dev HTTPS server running at https://localhost:${HTTPS_PORT}`);
  });

  // HTTP → HTTPS redirect
  http.createServer((req, res) => {
    const host = req.headers.host ? req.headers.host.split(':')[0] : 'localhost';
    const redirectUrl = `https://${host}:${HTTPS_PORT}${req.url}`;
    res.writeHead(301, { Location: redirectUrl });
    res.end();
  }).listen(HTTP_PORT, () => {
    console.log(`➡️ Dev HTTP redirect server running at http://localhost:${HTTP_PORT} -> https`);
  });
}

// Start the dev server
startHttpsServerDev();