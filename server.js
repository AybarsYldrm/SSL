'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');

const {
  parseOcspRequest, generateOcspResponse, parseCRL,
  pemToEcPriv, certInfoFromPem,
} = require('./index');

const PORT = 80;
const HOST = "94.138.209.225"; // VPS IP adresin

const certsDir = path.join(__dirname, 'certs');
const keysDir = path.join(__dirname, 'keys');

// ─────────────────────────────────────────────────────────────────────────────
// PKI durumunu diskten yükle
// ─────────────────────────────────────────────────────────────────────────────
function loadState() {
  const interCertPem = fs.readFileSync(path.join(certsDir, 'intermediate.pem'), 'utf8');
  const ocspCertPem  = fs.readFileSync(path.join(certsDir, 'ocsp.pem'), 'utf8');
  const ocspKeyPem   = fs.readFileSync(path.join(keysDir, 'ocsp.key'), 'utf8');
  const crlPem       = fs.readFileSync(path.join(certsDir, 'intermediate.crl'), 'utf8');

  const interInfo = certInfoFromPem(interCertPem);
  const ocspKey    = pemToEcPriv(ocspKeyPem);
  const ocspInfo   = certInfoFromPem(ocspCertPem);
  const crl        = parseCRL(crlPem);

  const issuerCA = {
    keyType: 'ec',
    name: interInfo.subjectNameDer,
    publicKeyBuf: _extractEcPubFromSpki(interInfo.spkiDer),
  };

  const responderKey = {
    keyType: 'ec', curveName: ocspKey.curveName, hashAlg: 'sha256',
    privateKey: ocspKey.privateKey, publicKeyBuf: ocspKey.publicKeyBuf,
  };

  return { 
    issuerCA, responderKey, ocspCertDer: ocspInfo.certDer, crl, 
    crlMtime: fs.statSync(path.join(certsDir, 'intermediate.crl')).mtimeMs 
  };
}

function _extractEcPubFromSpki(spkiDer) {
  const { readTLV, readChildren } = require('./src/asn1');
  const top = readTLV(spkiDer, 0);
  const children = readChildren(top.content);
  return children[1].content.subarray(1); // unused-bits baytı hariç
}

let state;
try {
  state = loadState();
  console.log('[PKI] Durum yüklendi: Ara CA, OCSP anahtarları ve CRL aktif.');
} catch (e) {
  console.error(`[PKI] Başlatılamadı: ${e.message}`);
  process.exit(1);
}

// CRL Yenileme Kontrolü
setInterval(() => {
  try {
    const mtime = fs.statSync(path.join(certsDir, 'intermediate.crl')).mtimeMs;
    if (mtime !== state.crlMtime) {
      state = loadState();
      console.log('[PKI] CRL değişikliği algılandı, bellek güncellendi.');
    }
  } catch (_) {}
}, 5000);

const server = http.createServer((req, res) => {
  const urlPath = req.url.split('?')[0]; // Query parametrelerini temizle

  // 1. OCSP İSTEKLERİ (POST)
  if (req.method === 'POST' && urlPath === '/ocsp' && req.headers['content-type'] === 'application/ocsp-request') {
    const body = [];
    req.on('data', chunk => body.push(chunk));
    req.on('error', () => { res.writeHead(400); res.end(); });

    req.on('end', () => {
      const ocspReqBuffer = Buffer.concat(body);
      console.log(`[OCSP] İstek alındı (${ocspReqBuffer.length} byte) - İstemci: ${req.socket.remoteAddress}`);

      let parsed;
      try { parsed = parseOcspRequest(ocspReqBuffer); } 
      catch (e) {
        res.writeHead(200, { 'Content-Type': 'application/ocsp-response' });
        return res.end(Buffer.from('30030a0101', 'hex')); // malformedRequest
      }

      const statusMap = new Map();
      for (const [serialHex, info] of state.crl.revoked) {
        statusMap.set(serialHex, { status: 'revoked', reason: info.reason, revokedAt: new Date() });
      }

      let respDer;
      try { respDer = generateOcspResponse(parsed, state.issuerCA, state.responderKey, state.ocspCertDer, statusMap); } 
      catch (e) {
        res.writeHead(200, { 'Content-Type': 'application/ocsp-response' });
        return res.end(Buffer.from('30030a0102', 'hex')); // internalError
      }

      res.writeHead(200, { 'Content-Type': 'application/ocsp-response', 'Content-Length': respDer.length });
      res.end(respDer);
      console.log(`[OCSP] Yanıt gönderildi.`);
    });
  }
  
  // 2. AIA - CA İHRAÇÇISI SERTİFİKASI İNDİRME (GET)
  else if (req.method === 'GET' && urlPath === '/ec-intermediate.crt') {
    const certPath = path.join(certsDir, 'intermediate.pem');
    if (fs.existsSync(certPath)) {
      res.writeHead(200, { 'Content-Type': 'application/x-x509-ca-cert' });
      res.end(fs.readFileSync(certPath));
      console.log(`[AIA] CA Sertifikası sunuldu (${req.socket.remoteAddress})`);
    } else {
      res.writeHead(404); res.end();
    }
  }

  // 3. CDP - CRL DOSYASI İNDİRME (GET)
  else if (req.method === 'GET' && urlPath.includes('/crl/ec-intermediate.crl')) {
    const crlPath = path.join(certsDir, 'intermediate.crl');
    if (fs.existsSync(crlPath)) {
      res.writeHead(200, { 'Content-Type': 'application/pkix-crl' });
      res.end(fs.readFileSync(crlPath));
      console.log(`[CDP] CRL Listesi sunuldu (${req.socket.remoteAddress})`);
    } else {
      res.writeHead(404); res.end();
    }
  }

  // 4. OCSP PING KONTROL (GET)
  else if (req.method === 'GET' && urlPath === '/ocsp') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Kurumsal PKI OCSP Yanıtlayıcısı Aktif.\n');
  } 
  
  else {
    res.writeHead(404); res.end();
  }
});

server.listen(PORT, HOST, () => {
  console.log(`╔══════════════════════════════════════════════════╗`);
  console.log(`║  SAF Node.js PKI & OCSP SUNUCUSU AKTİF           ║`);
  console.log(`║  Ağ Adresi : http://${HOST}:${PORT}               ║`);
  console.log(`║  AIA(OCSP) : http://${HOST}/ocsp                 ║`);
  console.log(`║  AIA(CA)   : http://${HOST}/ec-intermediate.crt  ║`);
  console.log(`║  CDP(CRL)  : http://${HOST}/crl/ec-intermediate.crl║`);
  console.log(`╚══════════════════════════════════════════════════╝`);
});