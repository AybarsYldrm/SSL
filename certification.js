'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const {
  generateRsaKeyPair, generateEcKeyPair,
  generateRootCA, generateEcIntermediateCA, generateEcEndEntityCert,
  generateCSR, generateCRL, newSerial,
  generateOcspResponse, parseOcspRequest, verifyOcspResponse,
} = require('./index');

const { buildCert } = require('./src/pki');
const {
  buildName, buildEcSPKI, computeEcSKID, extBasicConstraints,
  extKeyUsage, extSKID, extAKID, extEKU, extSAN, extCDP, extAIA, ext, OIDs, KU,
  SEQ, INT, intSmall, OCT, BIT, OID, CTX, NULL,
} = require('./src/asn1');
const { CURVES, _bigIntToFixedBuf } = require('./src/ec');
const { rsaPrivToPem, ecPrivToPem, crlToPem } = require('./src/keys');

function test(name, fn) {
  console.log(`\n▶ ${name}`);
  try { fn(); console.log('  └─ SONUÇ: GEÇTİ ✅'); }
  catch (e) { console.log(`  └─ SONUÇ: BAŞARISIZ ❌ — ${e.message}`); }
}
function assert(cond, msg) { if (!cond) throw new Error(msg || 'iddia başarısız'); }

console.log('\n╔══════════════════════════════════════════════════╗');
console.log('║  SAF KRİPTOGRAFİ, PKI, CRL & OCSP TEST PAKETİ  ║');
console.log('╚══════════════════════════════════════════════════╝');

// ─────────────────────────────────────────────────────────────────────────────
// PKI Zinciri Üretimi — RSA Kök CA → EC Ara CA (hibrit) → EC Sunucu / OCSP EE
// ─────────────────────────────────────────────────────────────────────────────
const certsDir = path.join(__dirname, 'certs');
const keysDir = path.join(__dirname, 'keys');
[certsDir, keysDir].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

// 1) RSA Kök CA
const rootCA = generateRootCA({ bits: 4096 });
fs.writeFileSync(path.join(keysDir, 'root.key'), rsaPrivToPem(rootCA));
fs.writeFileSync(path.join(certsDir, 'root.pem'), rootCA.certPem);

// 2) EC Ara CA — RSA Kök CA tarafından imzalanır (hibrit zincir).
//    Resmi pki.js fabrikası kullanılıyor: notBefore/notAfter, SKID/AKID,
//    BasicConstraints ve KeyUsage uzantıları otomatik ve doğru kuruluyor.
const interCA = generateEcIntermediateCA(rootCA, {
  curveName: 'P-256',
  commonName: 'Hibrit Ara CA',
});
fs.writeFileSync(path.join(keysDir, 'intermediate.key'), ecPrivToPem(interCA));
fs.writeFileSync(path.join(certsDir, 'intermediate.pem'), interCA.certPem);

// 3) Sunucu (EE) sertifikası — EC Ara CA tarafından imzalanır.
//    CRL Distribution Point (CDP) ve Authority Information Access (AIA)
//    uzantıları gömülüyor: istemciler bu sertifikayı aldığında, iptal
//    durumunu kontrol etmek için NEREYE gideceğini (CRL URL'i) ve/veya
//    OCSP responder'ın adresini sertifikanın içinden öğrenebilir.
//
//    generateEcEndEntityCert(crlUrl, aiaUrl) parametreleri kendi içinde
//    sabit dosya adlarıyla (`/ec-intermediate.crl`, `/ocsp`, `/ec-intermediate.crt`)
//    birleştiriyor — biz burada sadece TABAN URL'i veriyoruz.
const PKI_BASE_URL = 'http://intranet.fitfak.net';
const serverCert = generateEcEndEntityCert(interCA, 'ns.fitfak.net', {
  curveName: 'P-256',
  crlUrl: PKI_BASE_URL + '/crl',   // → CDP: http://pki.kurumsal.local/crl/ec-intermediate.crl
  aiaUrl: PKI_BASE_URL,            // → AIA OCSP: http://pki.kurumsal.local/ocsp
                                    // → AIA CA Issuers: http://pki.kurumsal.local/ec-intermediate.crt
});
fs.writeFileSync(path.join(keysDir, 'server.key'), ecPrivToPem(serverCert));
fs.writeFileSync(path.join(certsDir, 'server.pem'), serverCert.certPem);

// 4) OCSP Responder sertifikası — EC Ara CA tarafından imzalanır,
//    OCSP Signing EKU'su (1.3.6.1.5.5.7.3.9) ile kuruluyor.
const OCSP_SIGNING_OID = '2b06010505070309'; // id-kp-OCSPSigning
const ocspKey = generateEcKeyPair('P-256');
const ocspSkid = computeEcSKID(ocspKey.publicKeyBuf);
const ocspName = buildName([[OIDs.commonName, 'OCSP Responder']]);
const ocspCert = buildCert({
  serialNum: newSerial(),
  issuerName: interCA.name,
  subjectName: ocspName,
  spki: buildEcSPKI('P-256', ocspKey.publicKeyBuf),
  extensions: [
    extBasicConstraints(false),
    extKeyUsage([KU.digitalSignature]),
    extEKU([OCSP_SIGNING_OID]),
    extSKID(ocspSkid),
    extAKID(interCA.skid),
  ],
  signerKey: { keyType: 'ec', curveName: 'P-256', hashAlg: interCA.hashAlg, privateKey: interCA.privateKey },
});
fs.writeFileSync(path.join(keysDir, 'ocsp.key'), ecPrivToPem(ocspKey));
fs.writeFileSync(path.join(certsDir, 'ocsp.pem'), ocspCert.pem);

// OCSP responder anahtar bilgisini imzalama/doğrulama için tek objede topluyoruz
const ocspResponderKey = {
  keyType: 'ec', curveName: 'P-256', hashAlg: 'sha256',
  privateKey: ocspKey.privateKey, publicKey: ocspKey.publicKey,
  publicKeyBuf: ocspKey.publicKeyBuf, skid: ocspSkid,
};

// 5) CRL'ler
const REVOKED_SERIAL = BigInt('0x2000');
fs.writeFileSync(path.join(certsDir, 'root.crl'), generateCRL(rootCA, [{ serial: BigInt('0x1000'), reason: 4 }]));
fs.writeFileSync(path.join(certsDir, 'intermediate.crl'), generateCRL(interCA, [{ serial: REVOKED_SERIAL, reason: 1 }]));

// ─────────────────────────────────────────────────────────────────────────────
// TESTLER
// ─────────────────────────────────────────────────────────────────────────────
test('OCSP Sertifikası — Ara CA İmzası ve OCSPSigning EKU', () => {
  const ocspX509 = new crypto.X509Certificate(ocspCert.pem);
  const interX509 = new crypto.X509Certificate(interCA.certPem);

  assert(ocspX509.verify(interX509.publicKey), 'OCSP sertifikası Ara CA tarafından imzalanmamış!');
  console.log('  ├─ OCSP İmzası: Ara CA tarafından doğrulandı.');

  const ocspCheck = execSync(`openssl x509 -in ${path.join(certsDir, 'ocsp.pem')} -noout -ext extendedKeyUsage`).toString();
  assert(ocspCheck.includes('OCSP Signing'), 'OCSP Signing EKU\'su sertifikada bulunamadı!');
  console.log('  ├─ OCSP EKU (1.3.6.1.5.5.7.3.9) Doğrulandı.');
});

test('Tüm Sertifika Zinciri Doğrulaması (OpenSSL)', () => {
  const verify = execSync(`openssl verify -CAfile ${path.join(certsDir, 'root.pem')} -untrusted ${path.join(certsDir, 'intermediate.pem')} ${path.join(certsDir, 'server.pem')}`).toString();
  assert(verify.includes('OK'), 'Zincir doğrulanamadı!');
  console.log('  ├─ Zincir (root → intermediate → server): OK');
});

test('CDP / AIA Uzantıları — server.pem İçine Gömülü URL\'ler', () => {
  // CRL Distribution Points: istemcinin CRL'i nereden indireceğini bildirir.
  const cdpOut = execSync(`openssl x509 -in ${path.join(certsDir, 'server.pem')} -noout -ext crlDistributionPoints`).toString();
  assert(cdpOut.includes(PKI_BASE_URL + '/crl/ec-intermediate.crl'), `CDP URL'i sertifikada bulunamadı! Çıktı: ${cdpOut}`);
  console.log(`  ├─ CDP URI: ${PKI_BASE_URL}/crl/ec-intermediate.crl  ✔ gömülü`);

  // Authority Information Access: OCSP responder ve CA Issuers URL'lerini bildirir.
  const aiaOut = execSync(`openssl x509 -in ${path.join(certsDir, 'server.pem')} -noout -ext authorityInfoAccess`).toString();
  assert(aiaOut.includes('OCSP -') || aiaOut.includes('OCSP\n') || /\bOCSP\b/.test(aiaOut), `AIA içinde OCSP girdisi bulunamadı (OID yanlış kodlanmış olabilir)! Çıktı: ${aiaOut}`);
  assert(aiaOut.includes(PKI_BASE_URL + '/ocsp'), `AIA OCSP URL'i sertifikada bulunamadı! Çıktı: ${aiaOut}`);
  console.log(`  ├─ AIA OCSP URI: ${PKI_BASE_URL}/ocsp  ✔ gömülü (OID doğru tanındı: id-ad-ocsp)`);
  assert(aiaOut.includes('CA Issuers'), 'AIA içinde CA Issuers girdisi bulunamadı!');
  assert(aiaOut.includes(PKI_BASE_URL + '/ec-intermediate.crt'), `AIA CA Issuers URL'i sertifikada bulunamadı! Çıktı: ${aiaOut}`);
  console.log(`  ├─ AIA CA Issuers URI: ${PKI_BASE_URL}/ec-intermediate.crt  ✔ gömülü`);
});

test('CRL İmza Doğrulaması (OpenSSL)', () => {
  const crlPath = path.join(certsDir, 'intermediate.crl');
  const parseOut = execSync(`openssl crl -in ${crlPath} -noout -text`).toString();
  assert(parseOut.includes('Certificate Revocation List'), 'CRL openssl tarafından parse edilemedi!');
  console.log('  ├─ CRL Yapısı: openssl tarafından parse edildi.');

  const verifyOut = execSync(`openssl crl -in ${crlPath} -CAfile ${path.join(certsDir, 'intermediate.pem')} -noout 2>&1`).toString();
  assert(verifyOut.toLowerCase().includes('verify ok'), `CRL imzası Ara CA ile doğrulanamadı! Çıktı: ${verifyOut}`);
  console.log('  ├─ CRL İmzası: Ara CA public key ile doğrulandı (verify OK).');

  assert(parseOut.includes(REVOKED_SERIAL.toString(16)), 'İptal edilen seri numarası CRL içinde bulunamadı!');
  console.log(`  ├─ İptal Kaydı: seri 0x${REVOKED_SERIAL.toString(16)} CRL'de mevcut.`);
});

test('OCSP İmzalı Yanıt Üretimi ve Doğrulaması (good)', () => {
  const reqDerPath = path.join(certsDir, 'ocsp_req_good.der');
  execSync(`openssl ocsp -sha256 -issuer ${path.join(certsDir, 'intermediate.pem')} -cert ${path.join(certsDir, 'server.pem')} -reqout ${reqDerPath} -no_nonce`);
  const reqDer = fs.readFileSync(reqDerPath);

  const parsed = parseOcspRequest(reqDer);
  assert(parsed.requests.length === 1, 'OCSP isteğinde tam olarak 1 CertID bekleniyordu');
  console.log(`  ├─ İstek Çözümlendi: seri 0x${parsed.requests[0].serialNumber.toString(16)}`);

  const statusMap = new Map(); // boş → tüm sertifikalar "good"
  const respDer = generateOcspResponse(parsed, interCA, ocspResponderKey, ocspCert.der, statusMap);

  const result = verifyOcspResponse(respDer, ocspResponderKey);
  assert(result.ok, 'OCSP yanıt imzası, responder public anahtarı ile doğrulanamadı!');
  console.log('  ├─ OCSP Yanıt İmzası: responder anahtarıyla doğrulandı.');

  const respPath = path.join(certsDir, 'ocsp_resp_good.der');
  fs.writeFileSync(respPath, respDer);

  // Gerçek openssl ocsp CLI'siyle uçtan uca doğrulama (kendi parser'ımızdan
  // bağımsız, harici/bağımsız bir doğrulayıcı ile çapraz kontrol).
  const osslOut = execSync(`openssl ocsp -respin ${respPath} -CAfile ${path.join(certsDir, 'root.pem')} -verify_other ${path.join(certsDir, 'intermediate.pem')} 2>&1`).toString();
  assert(osslOut.includes('Response verify OK'), `openssl OCSP doğrulaması başarısız: ${osslOut}`);
  console.log('  ├─ OpenSSL CLI Çapraz Doğrulama: Response verify OK.');
});

test('OCSP İmzalı Yanıt Üretimi ve Doğrulaması (revoked)', () => {
  const fakeRequest = { requests: [{ serialNumber: REVOKED_SERIAL, hashAlgOid: OIDs.sha256 }] };
  const statusMap = new Map([
    [REVOKED_SERIAL.toString(16), { status: 'revoked', reason: 1, revokedAt: new Date() }],
  ]);
  const respDer = generateOcspResponse(fakeRequest, interCA, ocspResponderKey, ocspCert.der, statusMap);

  const result = verifyOcspResponse(respDer, ocspResponderKey);
  assert(result.ok, 'OCSP (revoked) yanıt imzası doğrulanamadı!');
  console.log('  ├─ OCSP Yanıt İmzası (revoked durumu): doğrulandı.');

  // Yanlış (yetkisiz) bir anahtarla doğrulama denemesi başarısız OLMALI
  const wrongKey = generateEcKeyPair('P-256');
  const wrongPub = { keyType: 'ec', curveName: 'P-256', hashAlg: 'sha256', publicKeyBuf: wrongKey.publicKeyBuf };
  const wrongResult = verifyOcspResponse(respDer, wrongPub);
  assert(!wrongResult.ok, 'GÜVENLİK HATASI: yanlış anahtarla doğrulama başarılı olmamalıydı!');
  console.log('  ├─ Negatif Test: yetkisiz anahtarla doğrulama doğru şekilde reddedildi.');

  const respPath = path.join(certsDir, 'ocsp_resp_revoked.der');
  fs.writeFileSync(respPath, respDer);

  const osslOut = execSync(`openssl ocsp -respin ${respPath} -text -CAfile ${path.join(certsDir, 'root.pem')} -verify_other ${path.join(certsDir, 'intermediate.pem')} 2>&1`).toString();
  assert(osslOut.includes('Response verify OK'), `openssl OCSP doğrulaması başarısız: ${osslOut}`);
  assert(osslOut.includes('Cert Status: revoked'), 'openssl çıktısında revoked durumu görünmüyor!');
  assert(osslOut.toLowerCase().includes('keycompromise'), 'Revocation Reason (keyCompromise) openssl çıktısında bulunamadı!');
  console.log('  ├─ OpenSSL CLI Çapraz Doğrulama: Response verify OK + Cert Status: revoked.');
});

test('CSR (PKCS#10) Üretimi ve OpenSSL Doğrulaması', () => {
  const csrKey = generateEcKeyPair('P-256');
  const csrPem = generateCSR(
    { keyType: 'ec', curveName: 'P-256', privateKey: csrKey.privateKey, publicKeyBuf: csrKey.publicKeyBuf },
    [[OIDs.commonName, 'csr-test.local']],
    [{ type: 'dns', value: 'csr-test.local' }],
  );
  const csrPath = path.join(certsDir, 'test.csr');
  fs.writeFileSync(csrPath, csrPem);

  const out = execSync(`openssl req -in ${csrPath} -noout -verify -text 2>&1`).toString();
  assert(out.toLowerCase().includes('verify ok'), 'CSR imzası openssl tarafından doğrulanamadı!');
  console.log('  ├─ CSR İmzası: openssl ile doğrulandı.');
  assert(out.includes('csr-test.local'), 'CSR içinde beklenen Common Name bulunamadı!');
  console.log('  ├─ CSR İçeriği: Common Name doğru.');
});