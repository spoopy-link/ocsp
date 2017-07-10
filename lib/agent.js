const http = require('http');
const https = require('https');
const rfc5280 = require('asn1.js/rfc5280');
const LRU = require('lru-cache');

const verify = require('./verify');
const check = require('./check');
const util = require('./util');
const request = require('./request');

class OCSPAgent extends https.Agent {
  constructor(options = {}) {
    super(options);
    this.caCache = new LRU(1024);
  }

  createConnection(port, host, options) {
    if (port !== null && typeof port === 'object') {
      options = port;
      port = null;
    } else if (host !== null && typeof host === 'object') {
      options = host;
      host = null;
    } else if (options === null || typeof options !== 'object') {
      options = {};
    }
    if (typeof port === 'number') options.port = port;
    if (typeof host === 'string') options.host = host;

    options.requestOCSP = true;
    const socket = super.createConnection(port, host, options);

    let stapling;
    socket.on('OCSPResponse', (data) => { stapling = data; });
    socket.on('secure', () => {
      this.handleOCSPResponse(socket, stapling)
      .then(() => socket.uncork())
      .catch((e) => socket.destroy(e));
    });

    socket.cork();
    return socket;
  }

  async handleOCSPResponse(socket, stapling) {
    if (!socket.ssl) return Promise.reject();
    let cert = socket.ssl.getPeerCertificate(true);
    let issuer = cert.issuerCertificate;
    cert = rfc5280.Certificate.decode(cert.raw, 'der');
    if (issuer) issuer = rfc5280.Certificate.decode(issuer.raw, 'der');

    function onIssuer(x509) {
      issuer = x509;
      return stapling ?
        verify({
          request: request.generate(cert, issuer),
          response: stapling,
        }) :
        check({ cert, issuer });
    }

    return issuer ?
      onIssuer(issuer) :
      this.fetchIssuer(cert, stapling).then(onIssuer);
  }

  fetchIssuer(cert, stapling) {
    const issuers = util['id-ad-caIssuers'].join('.');
    const uri = util.getAuthorityInfo(cert, issuers);
    const ca = this.caCache.get(uri);
    if (ca) return Promise.resolve(ca);
    return new Promise((resolve, reject) => {
      http.get(uri, (res) => {
        if (res.statusCode < 200 || res.statusCode >= 400) throw new Error(`Failed to fetch CA: ${res.statusCode}`)
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const cert = rfc5280.Certificate.decode(Buffer.concat(chunks), 'der');
          this.caCache.set(uri, cert);
          resolve(cert);
        });
      }).on('error', reject);
    });
  }
}

module.exports = OCSPAgent;
