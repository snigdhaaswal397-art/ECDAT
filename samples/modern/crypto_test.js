const crypto = require("crypto");

const hash = crypto.createHash("sha256");

const oldHash = crypto.createHash("md5");

const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    key,
    iv
);

crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048
});