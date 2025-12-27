// utils/encryption.js
require('dotenv').config();
const crypto = require('crypto');

const algorithm = 'aes-256-cbc';

// 1. Pre-process the Key and IV into BUFFERS once at startup
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY || '', 'utf8');
const STATIC_IV = Buffer.from(process.env.STATIC_IV || '', 'utf8');

if (ENCRYPTION_KEY.length !== 32) {
    console.error("❌ ENCRYPTION_KEY must be 32 bytes.");
    process.exit(1);
}
if (STATIC_IV.length !== 16) {
    console.error("❌ STATIC_IV must be 16 bytes.");
    process.exit(1);
}

function encrypt(text, isDeterministic = false) {
    if (!text) return text;
    
    // 2. Explicitly force the IV choice
    const iv = isDeterministic ? STATIC_IV : crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv(algorithm, ENCRYPTION_KEY, iv);
    
    let encrypted = cipher.update(String(text), 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // 3. DO NOT use Buffer.concat here for deterministic hex; use the hex string directly
    if (isDeterministic) {
        return encrypted; 
    }
    
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text, isDeterministic = false) {
    if (!text) return text;
    try {
        let iv, encryptedText;
        if (isDeterministic) {
            iv = STATIC_IV;
            encryptedText = text;
        } else {
            const parts = text.split(':');
            iv = Buffer.from(parts[0], 'hex');
            encryptedText = parts[1];
        }

        const decipher = crypto.createDecipheriv(algorithm, ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (err) {
        console.error("Decryption failed:", err.message);
        return null;
    }
}

module.exports = { encrypt, decrypt };