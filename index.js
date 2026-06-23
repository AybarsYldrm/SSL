'use strict';
/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  SAF KRİPTOGRAFİ & PKI MOTORU — Modül İhracatları              ║
 * ║  crypto modülü yok · sıfır harici bağımlılık                   ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 * Hash     : sha256, sha384, sha512
 * MAC/KDF  : hmac, hmac256/384/512, hkdf
 * Simetrik : gcmEncrypt, gcmDecrypt  (AES-128/192/256-GCM)
 * RSA      : generateRsaKeyPair(bits), rsaSign, rsaVerify,
 *            rsaOaepEncrypt, rsaOaepDecrypt
 * EC       : generateEcKeyPair(curve), ecdsaSign, ecdsaVerify,
 *            ecdhCompute (P-256/384/521)
 * X25519   : generateX25519KeyPair, x25519
 * PKI      : generateRootCA, generateIntermediateCA,
 *            generateEndEntityCert, generateEcRootCA,
 *            generateEcEndEntityCert, generateCSR, generateCRL,
 *            createCertificate
 * Rastgele : randomBytes
 */

// ── Temel ────────────────────────────────────────────────────────────────────
const { randomBytes, randomBigIntRange } = require('./src/random');

// ── Hash ─────────────────────────────────────────────────────────────────────
const { sha256, sha384, sha512, hashByName } = require('./src/hash');

// ── MAC / KDF ─────────────────────────────────────────────────────────────────
const {
  hmac, hmac256, hmac384, hmac512,
  hkdfExtract, hkdfExpand, hkdf,
} = require('./src/hmac');

// ── Simetrik (AES-GCM) ───────────────────────────────────────────────────────
const { gcmEncrypt, gcmDecrypt } = require('./src/aes');

// ── RSA ───────────────────────────────────────────────────────────────────────
const {
  generateRsaKeyPair, rsaSign, rsaVerify,
  rsaOaepEncrypt, rsaOaepDecrypt,
} = require('./src/rsa');

// ── EC / X25519 ───────────────────────────────────────────────────────────────
const {
  generateEcKeyPair, ecdsaSign, ecdsaVerify, ecdhCompute,
  generateX25519KeyPair, x25519,
  CURVES,
} = require('./src/ec');

// ── PKI ───────────────────────────────────────────────────────────────────────
const {
  generateRootCA, generateIntermediateCA, generateEndEntityCert,
  generateEcRootCA, generateEcIntermediateCA, generateEcEndEntityCert,
  generateCSR, generateCRL, parseCRL, createCertificate, newSerial,
  generateOcspResponse, parseOcspRequest, verifyOcspResponse,
} = require('./src/pki');

// ── Anahtar Serileştirme (PEM ↔ ham anahtar) ──────────────────────────────────
const {
  rsaPrivToPem, ecPrivToPem, crlToPem,
  pemToEcPriv, pemToRsaPriv, certInfoFromPem,
} = require('./src/keys');

// ── ASN.1 / DER ───────────────────────────────────────────────────────────────
const asn1 = require('./src/asn1');

// ─────────────────────────────────────────────────────────────────────────────
module.exports = {
  // Temel
  randomBytes, randomBigIntRange,

  // Hash
  sha256, sha384, sha512, hashByName,

  // MAC / KDF
  hmac, hmac256, hmac384, hmac512,
  hkdfExtract, hkdfExpand, hkdf,

  // Simetrik
  gcmEncrypt, gcmDecrypt,

  // RSA (2048 / 3072 / 4096)
  generateRsaKeyPair, rsaSign, rsaVerify,
  rsaOaepEncrypt, rsaOaepDecrypt,

  // EC (P-256 / P-384 / P-521)
  generateEcKeyPair, ecdsaSign, ecdsaVerify, ecdhCompute, CURVES,

  // X25519
  generateX25519KeyPair, x25519,

  // PKI
  generateRootCA, generateIntermediateCA, generateEndEntityCert,
  generateEcRootCA, generateEcIntermediateCA, generateEcEndEntityCert,
  generateCSR, generateCRL, parseCRL, createCertificate, newSerial,
  generateOcspResponse, parseOcspRequest, verifyOcspResponse,

  // Anahtar Serileştirme (PEM ↔ ham anahtar)
  rsaPrivToPem, ecPrivToPem, crlToPem,
  pemToEcPriv, pemToRsaPriv, certInfoFromPem,

  // ASN.1 / DER (ileri düzey kullanım)
  asn1,
};