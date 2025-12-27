// hash_utility.js
require('dotenv').config(); 
const bcrypt = require('bcrypt');
const { encrypt } = require('./utils/encryption');

const saltRounds = 10;
const plaintextUsername = 'profsmith'; // Exactly what you will type in the login box
const plaintextPassword = 'secure456'; // Exactly what you will type in the login box

async function generateFacultyData() {
    console.log("--- DEBUG INFO ---");
    console.log("Using Key:", process.env.ENCRYPTION_KEY);
    console.log("Using Static IV:", process.env.STATIC_IV);
    console.log("------------------");
    
    const encryptedUsername = encrypt(plaintextUsername, true);
    console.log(`\nEncrypted Username (Save this): ${encryptedUsername}`);

    const passwordHash = await bcrypt.hash(plaintextPassword, saltRounds);
    console.log(`Password Hash (Save this): ${passwordHash}`);
}

generateFacultyData();