const http = require('http');
const url = require('url');
const rfc2560 = require('asn1.js-rfc2560');

function getAuthorityInfo(cert, key) {
  let exts = cert.tbsCertificate.extensions || [];
  const infoAccess = exts.filter(({ extnID }) => extnID === 'authorityInformationAccess');
  if (!infoAccess.length) throw new Error('AuthorityInfoAccess not found in extensions');

  let res;
  const found = infoAccess.some(({ extnValue }) =>
    extnValue.some(({ accessMethod, accessLocation }) => {
      if (accessMethod.join('.') !== key) return false;
      const loc = accessLocation;
      if (loc.type !== 'uniformResourceIdentifier') return false;
      res = String(loc.value);
      return true;
    }));

  if (!found) throw new Error(`${key} not found in AuthorityInfoAccess`)
  return res;
}

function getResponse(uri, req) {
  return new Promise((resolve, reject) => {
    uri = url.parse(uri);

    const options = Object.assign({
      method: 'POST',
      headers: {
        'Content-Type': 'application/ocsp-request',
        'Content-Length': req.length,
      }
    }, uri);

    http.request(options, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 400) {
        reject(new Error(`Failed to obtain OCSP response: ${response.statusCode}`));
      }

      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    }).end(req);
  });
}

function parseResponse(raw) {
  const body = { start: 0, end: raw.length };
  const response = rfc2560.OCSPResponse.decode(raw, 'der', {
    track: function(key, start, end, type) {
      if (type !== 'content' || key !== 'responseBytes/response') return;
      body.start = start;
      body.end = end;
    },
  });

  const status = response.responseStatus;
  if (status !== 'successful') throw new Error(`Bad OCSP response status: ${status}`);

  // Unknown response type
  const responseType = response.responseBytes.responseType;
  if (responseType !== 'id-pkix-ocsp-basic') throw new Error(`Unknown OCSP response type: ${responseType}`);

  const bytes = response.responseBytes.response;

  const tbs = { start: body.start, end: body.end };
  const certsTbs = [];
  const basic = rfc2560.BasicOCSPResponse.decode(bytes, 'der', {
    track: function(key, start, end, type) {
      if (type !== 'tagged') return;
      if (key === 'tbsResponseData') {
        tbs.start = body.start + start;
        tbs.end = body.start + end;
      } else if (key === 'certs/tbsCertificate') {
        certsTbs.push({ start: body.start + start, end: body.start + end });
      }
    }
  });

  const OCSPSigning = module.exports['id-kp-OCSPSigning'].join('.');
  const certs = (basic.certs || []).filter(({tbsCertificate}) =>
    tbsCertificate.extensions.some(({extnID, extnValue}) => {
      if (extnID !== 'extendedKeyUsage') return false;
      return extnValue.some(value => value.join('.') === OCSPSigning);
    }));

  return {
    start: tbs.start,
    end: tbs.end,
    value: basic,
    certs, certsTbs,
  };
};

function toPEM(buf, label) {
  const p = buf.toString('base64');
  const out = [ `-----BEGIN ${label}-----` ];
  for (let i = 0; i < p.length; i += 64) out.push(p.slice(i, i + 64));
  out.push(`-----END ${label}-----`);
  return out.join('\n');
};

function toDER(raw, what) {
  let der = raw.toString().match(new RegExp(`-----BEGIN ${what}-----([^-]*)-----END ${what}-----`));
  if (der) der = new Buffer(der[1].replace(/[\r\n]/g, ''), 'base64');
  else if (typeof raw === 'string') der = new Buffer(raw);
  else der = raw;
  return der;
};

module.exports = {
  getAuthorityInfo,
  getResponse,
  parseResponse,
  toDER,
  toPEM,
  'id-ad-caIssuers': [ 1, 3, 6, 1, 5, 5, 7, 48, 2 ],
  'id-kp-OCSPSigning': [ 1, 3, 6, 1, 5, 5, 7, 3, 9 ],
  sign: {
    '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  },
};
