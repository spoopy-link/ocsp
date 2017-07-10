const util = require('./util');
const crypto = require('crypto');
const rfc2560 = require('asn1.js-rfc2560');
const rfc5280 = require('asn1.js-rfc5280');

function generate(rawCert, rawIssuer) {
  const cert = rawCert.tbsCertificate ? rawCert :
    rfc5280.Certificate.decode(util.toDER(rawCert, 'CERTIFICATE'), 'der');
  const issuer = rawIssuer.tbsCertificate ? rawIssuer :
    rfc5280.Certificate.decode(util.toDER(rawIssuer, 'CERTIFICATE'), 'der');

  const tbsCert = cert.tbsCertificate;
  const tbsIssuer = issuer.tbsCertificate;

  const certID = {
    hashAlgorithm: {
      // algorithm: [2, 16, 840, 1, 101, 3, 4, 2, 1]  // sha256
      algorithm: [1, 3, 14, 3, 2, 26]  // sha1
    },
    issuerNameHash: sha1(rfc5280.Name.encode(tbsCert.issuer, 'der')),
    issuerKeyHash: sha1(tbsIssuer.subjectPublicKeyInfo.subjectPublicKey.data),
    serialNumber: tbsCert.serialNumber,
  };

  const tbs = {
    version: 'v1',
    requestList: [{ reqCert: certID }],
    requestExtensions: [ {
      extnID: rfc2560['id-pkix-ocsp-nonce'],
      critical: false,
      extnValue: rfc2560.Nonce.encode(crypto.randomBytes(16), 'der')
    } ]
  };

  return {
    id: sha1(rfc2560.CertID.encode(certID, 'der')),
    data: rfc2560.OCSPRequest.encode({ tbsRequest: tbs }, 'der'),
    certID, cert, issuer,
  };
};

function sha1(data) {
  return crypto.createHash('sha1').update(data).digest();
}

module.exports = { generate };
