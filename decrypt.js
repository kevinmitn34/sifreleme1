const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function aesEncryptToBase64Hex(plainText, jwtToken, fixedIV) {
    // JWT'den key çek
    const decodedJwt = jwt.decode(jwtToken);
    if (!decodedJwt || !decodedJwt.key) {
        throw new Error("JWT içinde 'key' alanı bulunamadı.");
    }
    const jwtKey = decodedJwt.key;

    // Key ayarları
    const key = crypto.createHash('sha256').update(jwtKey).digest();

    // Sabit IV kullanımı
    const iv = Buffer.from(fixedIV, 'hex');

    // AES-256-CFB ile encrypt et
    const cipher = crypto.createCipheriv('aes-256-cfb', key, iv);
    let encrypted = cipher.update(plainText, 'utf-8', 'hex');
    encrypted += cipher.final('hex');

    // Hex'i Base64'e çevir
    const base64Value = Buffer.from(iv.toString('hex') + encrypted, 'hex').toString('base64');
    return base64Value;
}

function aesDecryptFromBase64Hex(encodedValue, jwtToken, fixedIV) {
    // JWT'den key çek
    const decodedJwt = jwt.decode(jwtToken);
    if (!decodedJwt || !decodedJwt.key) {
        throw new Error("JWT içinde 'key' alanı bulunamadı.");
    }
    const jwtKey = decodedJwt.key;

    // Base64'ten geri çevir
    const decodedBase64 = Buffer.from(encodedValue, 'base64').toString('hex');

    // Sabit IV'yi kullan
    const iv = Buffer.from(fixedIV, 'hex');

    // Şifrelenmiş metni ayır
    const encryptedText = decodedBase64.slice(32); // IV'den sonra kalan şifreli metin

    // Key ayarları
    const key = crypto.createHash('sha256').update(jwtKey).digest();

    // AES-256-CFB ile decrypt et
    const decipher = crypto.createDecipheriv('aes-256-cfb', key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');

    return decrypted;
}

// Sabit IV örneği
const fixedIV = '0123456789abcdef0123456789abcdef'; // 16 baytlık sabit IV
const jwtToken = "!!!!";

const encrypted = "ASNFZ4mrze8BI0VniavN726Ls5a7VlIM4MXU/GgLfcW3GlKDZ+c/CSQ7Mt1M14Q2ywgfEfKrHp4X"

const decrypted = aesDecryptFromBase64Hex(encrypted, jwtToken, fixedIV);
console.log("Çözülmüş Metin:", decrypted);
