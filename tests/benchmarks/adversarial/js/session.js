const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function keys() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}

function digest(buf) {
  return crypto.createHash('sha1').update(buf).digest('hex');
}

function seal(key, iv, data) {
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([c.update(data), c.final()]);
}

function agree() {
  const e = crypto.createECDH('prime256v1');
  return e.generateKeys();
}

function token(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'ES256' });
}

// the old version used 'md5' here; removed in 2025
module.exports = { keys, digest, seal, agree, token };
