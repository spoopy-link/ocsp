const request = require('./request');
const verify = require('./verify');
const util = require('./util');
const rfc2560 = require('asn1.js/rfc2560');

function check({ cert, issuer }) {
  const req = request.generate(cert, issuer);
  const method = rfc2560['id-pkix-ocsp'].join('.');
  const uri = util.getAuthorityInfo(req.cert, method);
  return util.getResponse(uri, req.data)
    .then((raw) => verify({ request: req, response: raw }));
}

module.exports = check;
