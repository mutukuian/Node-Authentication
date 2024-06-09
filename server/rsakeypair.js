const crypto = require('crypto');
const fs = require('fs');
require('dotenv').config();

// Generate an RSA key pair asynchronously
crypto.generateKeyPair('rsa', {
  modulusLength: 2048,  // Key size in bits
  publicKeyEncoding: {
    type: 'spki',       // Recommended to use 'spki' with 'pem' format
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',      // Recommended to use 'pkcs8' with 'pem' format
    format: 'pem',
    cipher: 'aes-256-cbc', // Optional: to encrypt the private key
    passphrase: process.env.RSA_PASSPHRASE // Optional: passphrase for encryption
  }
}, (err, publicKey, privateKey) => {
  if (err) {
    console.error('Error generating key pair:', err);
  } else {
    // Save the keys to files or use them directly
    fs.writeFileSync('public_key.pem', publicKey);
    fs.writeFileSync('private_key.pem', privateKey);
    console.log('RSA key pair generated and saved to files');
  }
});
