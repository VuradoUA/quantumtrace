// Helpers used by the legacy admin UI.
const crypto = require("crypto");

function fingerprint(buf) {
  return crypto.createHash("md5").update(buf).digest("hex");
}

function checksum(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function seal(key, iv, text) {
  const c = crypto.createCipheriv("aes-128-cbc", key, iv);
  return Buffer.concat([c.update(text), c.final()]);
}

module.exports = { fingerprint, checksum, seal };
