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

const SC_ENCRYPTION_MATERIAL_FIELDS = [
  'ltk',
  'secureConnections',
  'authenticated',
  'bonded',
  'keySize'
];

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
    this._pendingScEncryptionMaterial = null;

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
      this.clearPendingScEncryptionMaterial();
      this.updateSecurityState(INITIAL_SECURITY_STATE);
      this.emit('end');
    }
  }

  pushEncrypt(encrypt) {
    const encrypted = !!encrypt;

    if (!encrypted) {
      this.clearPendingScEncryptionMaterial();
      this.updateSecurityState(INITIAL_SECURITY_STATE);
      return;
    }

    if (!this._pendingScEncryptionMaterial) {
      this.updateSecurityState({
        encrypted: true
      });
      return;
    }

    const pending = this._pendingScEncryptionMaterial;

    try {
      this.updateSecurityState({
        encrypted: true,
        secureConnections: pending.secureConnections,
        authenticated: pending.authenticated,
        bonded: pending.bonded,
        keySize: pending.keySize
      });
    } finally {
      this.clearPendingScEncryptionMaterial();
    }
  }

  setPendingScEncryptionMaterial(material) {
    if (!material || typeof material !== 'object' ||
        Array.isArray(material) || Buffer.isBuffer(material)) {
      throw new TypeError('SC encryption material must be an object');
    }

    if (this._pendingScEncryptionMaterial) {
      throw new Error('SC encryption material is already pending');
    }

    const fields = Object.keys(material);

    if (fields.length !== SC_ENCRYPTION_MATERIAL_FIELDS.length ||
        SC_ENCRYPTION_MATERIAL_FIELDS.some((field) => {
          return fields.indexOf(field) === -1;
        })) {
      throw new TypeError('SC encryption material fields are invalid');
    }

    if (!Buffer.isBuffer(material.ltk)) {
      throw new TypeError('ltk must be a Buffer');
    }

    if (material.ltk.length !== 16) {
      throw new RangeError('ltk must be 16 bytes');
    }

    [
      'secureConnections',
      'authenticated',
      'bonded'
    ].forEach((field) => {
      if (typeof material[field] !== 'boolean') {
        throw new TypeError(field + ' must be a boolean');
      }
    });

    if (material.secureConnections !== true ||
        material.authenticated !== false ||
        material.bonded !== false) {
      throw new RangeError(
        'SC encryption metadata must describe unbonded Just Works'
      );
    }

    if (typeof material.keySize !== 'number') {
      throw new TypeError('keySize must be a number');
    }

    if (!Number.isInteger(material.keySize) ||
        material.keySize < 7 || material.keySize > 16) {
      throw new RangeError(
        'keySize must be an integer from 7 to 16'
      );
    }

    this._pendingScEncryptionMaterial = {
      ltk: Buffer.from(material.ltk),
      secureConnections: true,
      authenticated: false,
      bonded: false,
      keySize: material.keySize
    };
  }

  hasPendingScEncryptionMaterial() {
    return this._pendingScEncryptionMaterial !== null;
  }

  takePendingScLtk() {
    if (!this._pendingScEncryptionMaterial) {
      throw new Error('SC encryption material is not pending');
    }

    if (!this._pendingScEncryptionMaterial.ltk) {
      throw new Error('pending SC LTK has already been taken');
    }

    const ltk = Buffer.from(this._pendingScEncryptionMaterial.ltk);

    this._pendingScEncryptionMaterial.ltk.fill(0);
    this._pendingScEncryptionMaterial.ltk = null;

    return ltk;
  }

  clearPendingScEncryptionMaterial() {
    if (!this._pendingScEncryptionMaterial) {
      return;
    }

    if (this._pendingScEncryptionMaterial.ltk) {
      this._pendingScEncryptionMaterial.ltk.fill(0);
    }

    this._pendingScEncryptionMaterial = null;
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
    this.clearPendingScEncryptionMaterial();
    this.updateSecurityState(INITIAL_SECURITY_STATE);
    this.emit('ltkNegReply');
  }
}

module.exports = AclStream;
