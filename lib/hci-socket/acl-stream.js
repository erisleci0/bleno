const debug = require('debug')('acl-att-stream');

const { EventEmitter } = require('events');

const crypto = require('./crypto');
const Smp = require('./smp');

const SECURITY_BOOLEAN_FIELDS = [
  'encrypted',
  'secureConnections',
  'authenticated',
  'bonded'
];

const SECURITY_FIELDS = SECURITY_BOOLEAN_FIELDS.concat(['keySize']);

const INITIAL_SECURITY_STATE = Object.freeze({
  encrypted: false,
  secureConnections: false,
  authenticated: false,
  bonded: false,
  keySize: 0
});

class AclStream extends EventEmitter {
  constructor(hci, handle, localAddressType, localAddress, remoteAddressType, remoteAddress) {
    super();
    this._hci = hci;
    this._handle = handle;
    this._securityState = INITIAL_SECURITY_STATE;

    this._smp = new Smp(this, localAddressType, localAddress, remoteAddressType, remoteAddress);
  }

  get encrypted() {
    return this._securityState.encrypted;
  }

  get security() {
    return Object.freeze(Object.assign({}, this._securityState));
  }

  write(cid, data) {
    this._hci.queueAclDataPkt(this._handle, cid, data);
  }

  push(cid, data) {
    if (data) {
      this.emit('data', cid, data);
    } else {
      this.emit('end');
    }
  }

  pushEncrypt(encrypt) {
    this.updateSecurityState({
      encrypted: !!encrypt
    });
  }

  updateSecurityState(update) {
    if (!update || typeof update !== 'object' ||
        Array.isArray(update) || Buffer.isBuffer(update)) {
      throw new TypeError('security state update must be an object');
    }

    const fields = Object.keys(update);

    fields.forEach((field) => {
      if (SECURITY_FIELDS.indexOf(field) === -1) {
        throw new TypeError('unknown security state field: ' + field);
      }

      if (SECURITY_BOOLEAN_FIELDS.indexOf(field) !== -1 &&
          typeof update[field] !== 'boolean') {
        throw new TypeError(field + ' must be a boolean');
      }

      if (field === 'keySize') {
        if (typeof update.keySize !== 'number') {
          throw new TypeError('keySize must be a number');
        }

        if (!Number.isInteger(update.keySize) ||
            (update.keySize !== 0 &&
             (update.keySize < 7 || update.keySize > 16))) {
          throw new RangeError('keySize must be 0 or an integer from 7 to 16');
        }
      }
    });

    const changed = fields.some((field) => {
      return this._securityState[field] !== update[field];
    });

    if (!changed) {
      return this.security;
    }

    const encryptedChanged = fields.indexOf('encrypted') !== -1 &&
      this._securityState.encrypted !== update.encrypted;

    this._securityState = Object.freeze(Object.assign(
      {},
      this._securityState,
      update
    ));

    const snapshot = this.security;

    if (encryptedChanged) {
      this.emit('encryptChange', this.encrypted);
    }

    this.emit('securityChange', snapshot);

    return snapshot;
  }

  pushLtkNegReply() {
    this.emit('ltkNegReply');
  }
}

module.exports = AclStream;
