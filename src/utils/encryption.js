const crypto = require('crypto');


const secretKey = crypto.createHash('sha256').update(process.env.SECRET_KEY || '').digest(); // Ensure the key is 32 bytes
const ALGORITHM = 'aes-256-ctr';
const IV_LENGTH = 16; // AES block size is 16 bytes



// Encrypt data for database function
 const encrypt = (data) => {
    if (typeof data === 'object') {
        data = JSON.stringify(data);
    }
    const iv = crypto.randomBytes(IV_LENGTH); // Initialization vector
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(secretKey), iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + encrypted; // Prepend IV to the encrypted text
};

// Decrypt function
 const decrypt = (encryptedData) => {
    try{
        if (typeof encryptedData === 'object') {
            encryptedData = JSON.stringify(encryptedData);
        }

        const iv = Buffer.from(encryptedData.slice(0, IV_LENGTH * 2), 'hex'); // Extract the IV from the encrypted text
        const encrypted = encryptedData.slice(IV_LENGTH * 2); // Extract the actual encrypted text
        const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(secretKey), iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }catch(error){
        console.log(error.message)
        
    }
};



// Load encryption keys from environment variables
// Encrypt data for data exchange
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "BACKEND_ENC@YPT_KeY_123";
const DECRYPTION_KEY = process.env.DECRYPTION_KEY || "REFIN3_DEC@YPT_KeY_456";
/**
 * Encrypts a JSON object.
 * @param {Object} data - The JSON object to be encrypted.
 * @returns {string} - The encrypted string.
 */
const encryptData = (data) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(JSON.stringify(data));
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
};

/**
 * Decrypts an encrypted string.
 * @param {string} encryptedData - The encrypted string.
 * @returns {Object} - The decrypted JSON object.
 */
const decryptData = (encryptedData) => {
    const [ivHex, encrypted] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(DECRYPTION_KEY), iv);
    let decrypted = decipher.update(Buffer.from(encrypted, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return JSON.parse(decrypted.toString());
};

module.exports = { 
    encrypt,
    decrypt
};
