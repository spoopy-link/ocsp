const kcode = Symbol('code');

class OCSPError extends Error {
  constructor(code, message) {
    super(message);
    this[kcode] = code;
  }

  get code() {
    return this[kcode];
  }
}

module.exports = OCSPError;
