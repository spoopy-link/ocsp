const util = require('./util');
const rfc5280 = require('asn1.js-rfc5280');
const crypto = require('crypto');
const OCSPError = require('./OCSPError');

function findResponder({ tbsCertificate }, certs, raws) {
  let issuerKey = tbsCertificate.subjectPublicKeyInfo;
  issuerKey = util.toPEM(rfc5280.SubjectPublicKeyInfo.encode(issuerKey, 'der'), 'PUBLIC KEY');

  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i];
    const signAlg = util.sign[cert.signatureAlgorithm.algorithm.join('.')];
    if (!signAlg) throw new Error(`Unknown signature algorithm ${cert.signatureAlgorithm.algorithm}`);

    const v = crypto.createVerify(signAlg);

    v.update(raws[i]);
    if (!v.verify(issuerKey, cert.signature.data)) throw new Error('Invalid signature');

    let certKey = cert.tbsCertificate.subjectPublicKeyInfo;
    certKey = util.toPEM(rfc5280.SubjectPublicKeyInfo.encode(certKey, 'der'), 'PUBLIC KEY');
    return certKey;
  }

  return issuerKey;
}

function verify(options) {
  const req = options.request;
  let issuer = req.issuer || rfc5280.Certificate.decode(util.toDER(options.issuer, 'CERTIFICATE'), 'der');
  let res = util.parseResponse(options.response);

  const rawTBS = options.response.slice(res.start, res.end);
  const certs = res.certs;
  const raws = res.certsTbs.map(({ start, end }) => options.response.slice(start, end));
  res = res.value;

  const signAlg = util.sign[res.signatureAlgorithm.algorithm.join('.')];
  if (!signAlg) {
    throw new Error(`Unknown signature algorithm ${res.signatureAlgorithm.algorithm}`);
    return;
  }

  const responderKey = findResponder(issuer, certs, raws);
  const v = crypto.createVerify(signAlg);
  const tbs = res.tbsResponseData;
  const signature = res.signature.data;
  v.update(rawTBS);

  if (!v.verify(responderKey, signature)) throw new OCSPError('OCSP_INVALID_SIGNATURE', 'Invalid signature');
  if (!tbs.responses.length) throw new Error('Expected at least one response');

  res = tbs.responses[0];

  if (res.certId.hashAlgorithm.algorithm.join('.') !== req.certID.hashAlgorithm.algorithm.join('.')) {
    throw new OCSPError('OCSP_ALGORITHM_MISMATCH', 'Hash algorithm mismatch');
  }

  if (res.certId.issuerNameHash.toString('hex') !== req.certID.issuerNameHash.toString('hex')) {
    throw new OCSPError('OCSP_ISSUER_NAME_MISMATCH', 'Issuer name hash mismatch');
  }

  if (res.certId.issuerKeyHash.toString('hex') !== req.certID.issuerKeyHash.toString('hex')) {
    throw new OCSPError('OCSP_ISSUER_KEY_MISMATCH', 'Issuer key hash mismatch');
  }

  if (res.certId.serialNumber.cmp(req.certID.serialNumber) !== 0) {
    throw new OCSPError('OCSP_SERIAL_NUMBER_MISMATCH', 'Serial number mismatch');
  }

  if (res.certStatus.type !== 'good') {
    throw new OCSPError('OCSP_INVALID_STATUS', `OCSP Status: ${res.certStatus.type}`);
  }

  const now = +new Date();
  const nudge = options.nudge || 60000;
  if (res.thisUpdate - nudge > now || res.nextUpdate + nudge < now) {
    throw new OCSPError('OCSP_RESPONSE_EXPIRED', 'OCSP Response expired');
  }

  return null;
}

module.exports = verify;
