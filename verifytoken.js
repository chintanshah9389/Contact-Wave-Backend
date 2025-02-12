const crypto = require('crypto');

function generateVerificationToken() {
  return crypto.randomBytes(20).toString('hex'); // Generates a 20-byte long random hex string
}

const verificationToken = generateVerificationToken();
console.log('Generated Verification Token:', verificationToken);