const debug = require('debug')('smp');

const nodeCrypto = require('crypto');
const { EventEmitter } = require('events');

const crypto = require('./crypto');
const mgmt = require('./mgmt');

const SMP_CID = 0x0006;

const SMP_PAIRING_REQUEST = 0x01;
const SMP_PAIRING_RESPONSE = 0x02;
const SMP_PAIRING_CONFIRM = 0x03;
const SMP_PAIRING_RANDOM = 0x04;
const SMP_PAIRING_FAILED = 0x05;
const SMP_ENCRYPT_INFO = 0x06;
const SMP_MASTER_IDENT = 0x07;
const SMP_PAIRING_PUBLIC_KEY = 0x0c;
const SMP_PAIRING_DHKEY_CHECK = 0x0d;
const SMP_PAIRING_KEYPRESS_NOTIFICATION = 0x0e;

const SC_UNSUPPORTED_COMMANDS = [
  SMP_PAIRING_RESPONSE,
  SMP_ENCRYPT_INFO,
  SMP_MASTER_IDENT,
  0x08, // Identity Information
  0x09, // Identity Address Information
  0x0a, // Signing Information
  0x0b, // Security Request
  SMP_PAIRING_KEYPRESS_NOTIFICATION
];

const SMP_OOB_NOT_AVAILABLE = 0x02;
const SMP_ENCRYPTION_KEY_SIZE = 0x06;
const SMP_COMMAND_NOT_SUPPORTED = 0x07;
const SMP_UNSPECIFIED = 0x08;
const SMP_INVALID_PARAMETERS = 0x0a;
const SMP_DHKEY_CHECK_FAILED = 0x0b;

const PAIRING_MODE_NONE = 'none';
const PAIRING_MODE_LEGACY = 'legacy';
const PAIRING_MODE_SC = 'secureConnections';

const PAIRING_STAGE_IDLE = 'idle';
const PAIRING_STAGE_FEATURES_EXCHANGED =
  'pairingFeaturesExchanged';
const PAIRING_STAGE_PEER_PUBLIC_KEY = 'peerPublicKeyReceived';
const PAIRING_STAGE_LOCAL_CONFIRM = 'localConfirmSent';
const PAIRING_STAGE_PEER_RANDOM = 'peerRandomReceived';
const PAIRING_STAGE_LOCAL_RANDOM = 'localRandomSent';
const PAIRING_STAGE_PEER_DHKEY_CHECK =
  'peerDhKeyCheckVerified';
const PAIRING_STAGE_LOCAL_DHKEY_CHECK = 'localDhKeyCheckSent';
const PAIRING_STAGE_ENCRYPTION_MATERIAL =
  'encryptionMaterialHandedOff';
const PAIRING_STAGE_WAITING_FOR_ENCRYPTION =
  'waitingForEncryption';

const SC_AUTHREQ_BIT = 0x08;
const SC_PAIRING_TIMEOUT_MS = 30000;

const SC_STAGE_KEY_EXCHANGE_PENDING = 'keyExchangePending';
const SC_STAGE_KEY_EXCHANGE_COMPLETE = 'keyExchangeComplete';
const SC_STAGE_LOCAL_CONFIRM_READY = 'localConfirmReady';
const SC_STAGE_LOCAL_CONFIRM_BUILT = 'localConfirmBuilt';
const SC_STAGE_PEER_RANDOM_RECEIVED = 'peerRandomReceived';
const SC_STAGE_CONFIRM_RANDOM_COMPLETE = 'confirmRandomComplete';
const SC_STAGE_DHKEY_MATERIAL_READY = 'dhKeyMaterialReady';
const SC_STAGE_PEER_DHKEY_CHECK_VERIFIED = 'peerDhKeyCheckVerified';
const SC_STAGE_DHKEY_CHECK_COMPLETE = 'dhKeyCheckComplete';
const SC_STAGE_LTK_HANDED_OFF = 'ltkHandedOff';

// Bluetooth LE Secure Connections debug public key in MSO-first format.
const SC_DEBUG_PUBLIC_KEY = Buffer.from(
  '20b003d2f297be2c5e2c83a7e9f9a5b9' +
  'eff49111acf4fddbcc0301480e359de6' +
  'dc809c49652aeb6d63329abf5a52155c' +
  '766345c28fed3024741c8ed01589d28b',
  'hex'
);

function assertBuffer(value, name) {
  if (!Buffer.isBuffer(value)) {
    throw new TypeError(name + ' must be a Buffer');
  }
}

function assertLength(value, length, name) {
  assertBuffer(value, name);

  if (value.length !== length) {
    throw new RangeError(name + ' must be ' + length + ' bytes');
  }
}

function reverseSmpValue(value) {
  assertBuffer(value, 'value');

  if (value.length !== 16 && value.length !== 32) {
    throw new RangeError('value must be 16 or 32 bytes');
  }

  return Buffer.from(value).reverse();
}

function msoToSmp(value) {
  return reverseSmpValue(value);
}

function smpToMso(value) {
  return reverseSmpValue(value);
}

function convertP256PublicKey(publicKey) {
  assertLength(publicKey, 64, 'publicKey');

  const output = Buffer.alloc(64);

  for (let i = 0; i < 32; i++) {
    output[i] = publicKey[31 - i];
    output[32 + i] = publicKey[63 - i];
  }

  return output;
}

function p256PublicKeyMsoToSmp(publicKey) {
  return convertP256PublicKey(publicKey);
}

function p256PublicKeySmpToMso(publicKey) {
  return convertP256PublicKey(publicKey);
}

function buildPairingPublicKeyPdu(publicKey) {
  return Buffer.concat([
    Buffer.from([SMP_PAIRING_PUBLIC_KEY]),
    p256PublicKeyMsoToSmp(publicKey)
  ]);
}

function parsePairingPublicKeyPdu(pdu) {
  assertLength(pdu, 65, 'pdu');

  if (pdu[0] !== SMP_PAIRING_PUBLIC_KEY) {
    throw new RangeError('pdu must use the Pairing Public Key opcode');
  }

  return p256PublicKeySmpToMso(pdu.slice(1));
}

function buildPairingDhKeyCheckPdu(dhKeyCheck) {
  assertLength(dhKeyCheck, 16, 'dhKeyCheck');

  return Buffer.concat([
    Buffer.from([SMP_PAIRING_DHKEY_CHECK]),
    msoToSmp(dhKeyCheck)
  ]);
}

function parsePairingDhKeyCheckPdu(pdu) {
  assertLength(pdu, 17, 'pdu');

  if (pdu[0] !== SMP_PAIRING_DHKEY_CHECK) {
    throw new RangeError('pdu must use the Pairing DHKey Check opcode');
  }

  return smpToMso(pdu.slice(1));
}

function buildPairingConfirmPdu(confirm) {
  assertLength(confirm, 16, 'confirm');

  return Buffer.concat([
    Buffer.from([SMP_PAIRING_CONFIRM]),
    msoToSmp(confirm)
  ]);
}

function parsePairingConfirmPdu(pdu) {
  assertLength(pdu, 17, 'pdu');

  if (pdu[0] !== SMP_PAIRING_CONFIRM) {
    throw new RangeError('pdu must use the Pairing Confirm opcode');
  }

  return smpToMso(pdu.slice(1));
}

function buildPairingRandomPdu(nonce) {
  assertLength(nonce, 16, 'nonce');

  return Buffer.concat([
    Buffer.from([SMP_PAIRING_RANDOM]),
    msoToSmp(nonce)
  ]);
}

function parsePairingRandomPdu(pdu) {
  assertLength(pdu, 17, 'pdu');

  if (pdu[0] !== SMP_PAIRING_RANDOM) {
    throw new RangeError('pdu must use the Pairing Random opcode');
  }

  return smpToMso(pdu.slice(1));
}

function buildScAddress(addressType, address) {
  assertLength(addressType, 1, 'addressType');
  assertLength(address, 6, 'address');

  if (addressType[0] !== 0x00 && addressType[0] !== 0x01) {
    throw new RangeError('addressType must be public or random');
  }

  return Buffer.concat([
    Buffer.from(addressType),
    Buffer.from(address).reverse()
  ]);
}

function buildScIoCap(pairingPdu, opcode, name) {
  assertLength(pairingPdu, 7, name);

  if (pairingPdu[0] !== opcode) {
    throw new RangeError(name + ' has an invalid opcode');
  }

  return Buffer.from([
    pairingPdu[3],
    pairingPdu[2],
    pairingPdu[1]
  ]);
}

function getNegotiatedScKeySize(pairingRequest, pairingResponse) {
  const requestKeySize = pairingRequest[4];
  const responseKeySize = pairingResponse[4];

  if (requestKeySize < 7 || requestKeySize > 16) {
    throw new RangeError(
      'pairingRequest maximum encryption key size must be 7 to 16'
    );
  }

  if (responseKeySize < 7 || responseKeySize > 16) {
    throw new RangeError(
      'pairingResponse maximum encryption key size must be 7 to 16'
    );
  }

  return Math.min(requestKeySize, responseKeySize);
}

class Smp extends EventEmitter {
  constructor(aclStream, localAddressType, localAddress, remoteAddressType, remoteAddress) {
    super();

    this._aclStream = aclStream;

    this._iat = Buffer.from([(remoteAddressType === 'random') ? 0x01 : 0x00]);
    this._ia = Buffer.from(remoteAddress.split(':').reverse().join(''), 'hex');
    this._rat = Buffer.from([(localAddressType === 'random') ? 0x01 : 0x00]);
    this._ra = Buffer.from(localAddress.split(':').reverse().join(''), 'hex');

    this._stk = null;
    this._random = null;
    this._diversifier = null;
    this._scKeyExchange = null;
    this._pairingMode = PAIRING_MODE_NONE;
    this._pairingStage = PAIRING_STAGE_IDLE;
    this._pairingTimer = null;
    this._pairingFailed = false;
    this._pairingTimedOut = false;
    this._preq = null;
    this._pres = null;
    this._pcnf = null;
    this._tk = null;
    this._r = null;

    this.onAclStreamDataBinded = this.onAclStreamData.bind(this);
    this.onAclStreamEncryptChangeBinded = this.onAclStreamEncryptChange.bind(this);
    this.onAclStreamLtkNegReplyBinded = this.onAclStreamLtkNegReply.bind(this);
    this.onAclStreamEndBinded = this.onAclStreamEnd.bind(this);

    this._aclStream.on('data', this.onAclStreamDataBinded);
    this._aclStream.on('encryptChange', this.onAclStreamEncryptChangeBinded);
    this._aclStream.on('ltkNegReply', this.onAclStreamLtkNegReplyBinded);
    this._aclStream.on('end', this.onAclStreamEndBinded);
  }

  onAclStreamData(cid, data) {
    if (cid !== SMP_CID) {
      return;
    }

    if (this._pairingTimedOut) {
      return;
    }

    if (!Buffer.isBuffer(data) || data.length === 0) {
      if (this._pairingMode === PAIRING_MODE_SC) {
        this.failScPairing(SMP_INVALID_PARAMETERS);
      }

      return;
    }

    const code = data.readUInt8(0);

    if (SMP_PAIRING_REQUEST === code) {
      this.handlePairingRequest(data);
      return;
    }

    if (SMP_PAIRING_FAILED === code) {
      this.handlePairingFailed(data);
      return;
    }

    if (this._pairingFailed) {
      return;
    }

    if (this._pairingMode === PAIRING_MODE_LEGACY) {
      if (SMP_PAIRING_CONFIRM === code) {
        this.handlePairingConfirm(data);
      } else if (SMP_PAIRING_RANDOM === code) {
        this.handlePairingRandom(data);
      } else if (SMP_PAIRING_PUBLIC_KEY === code ||
                 SMP_PAIRING_DHKEY_CHECK === code) {
        this.failLegacyPairing(SMP_COMMAND_NOT_SUPPORTED);
      }

      return;
    }

    if (this._pairingMode !== PAIRING_MODE_SC) {
      return;
    }

    if (SMP_PAIRING_PUBLIC_KEY === code) {
      this.handleScPublicKey(data);
    } else if (SMP_PAIRING_RANDOM === code) {
      this.handleScRandom(data);
    } else if (SMP_PAIRING_DHKEY_CHECK === code) {
      this.handleScDhKeyCheck(data);
    } else if (SMP_PAIRING_CONFIRM === code) {
      this.failScPairing(SMP_INVALID_PARAMETERS);
    } else if (SC_UNSUPPORTED_COMMANDS.indexOf(code) !== -1) {
      this.failScPairing(SMP_COMMAND_NOT_SUPPORTED);
    }
  }

  onAclStreamEncryptChange(encrypted) {
    if (!encrypted) {
      return;
    }

    if (this._pairingMode === PAIRING_MODE_LEGACY &&
        this._stk && this._diversifier && this._random) {
      this.write(Buffer.concat([
        Buffer.from([SMP_ENCRYPT_INFO]),
        this._stk
      ]));

      this.write(Buffer.concat([
        Buffer.from([SMP_MASTER_IDENT]),
        this._diversifier,
        this._random
      ]));

      this.resetLegacyPairing();
      this.finishPairingAttempt();
      return;
    }

    if (this._pairingMode === PAIRING_MODE_SC &&
        this._pairingStage ===
          PAIRING_STAGE_WAITING_FOR_ENCRYPTION &&
        this._scKeyExchange &&
        this._scKeyExchange.confirmRandomStage ===
          SC_STAGE_LTK_HANDED_OFF) {
      this.clearPairingTimer();
      this.resetScKeyExchange();
      this.resetLegacyPairing();
      this.finishPairingAttempt();
    }
  }

  onAclStreamLtkNegReply() {
    if (this._pairingFailed || this._pairingTimedOut) {
      this.resetScKeyExchange();
      return;
    }

    if (this._pairingMode === PAIRING_MODE_SC) {
      this.failScPairing(SMP_UNSPECIFIED);
      return;
    }

    this.resetScKeyExchange();

    this.write(Buffer.from([
      SMP_PAIRING_FAILED,
      SMP_UNSPECIFIED
    ]));

    this.emit('fail');
  }

  onAclStreamEnd() {
    this.clearPairingTimer();
    this.resetScKeyExchange();
    this.resetLegacyPairing();
    this.finishPairingAttempt();

    this._aclStream.removeListener('data', this.onAclStreamDataBinded);
    this._aclStream.removeListener('encryptChange', this.onAclStreamEncryptChangeBinded);
    this._aclStream.removeListener('ltkNegReply', this.onAclStreamLtkNegReplyBinded);
    this._aclStream.removeListener('end', this.onAclStreamEndBinded);
  }

  handlePairingRequest(data) {
    if (this._pairingMode !== PAIRING_MODE_NONE) {
      if (this._pairingMode === PAIRING_MODE_SC) {
        this.failScPairing(SMP_INVALID_PARAMETERS);
      } else {
        this.failLegacyPairing(SMP_INVALID_PARAMETERS);
      }

      return;
    }

    this._pairingFailed = false;

    const failureReason = this.validatePairingRequest(data);

    if (failureReason !== null) {
      this.failPairingBeforeMode(failureReason);
      return;
    }

    if (data[3] & SC_AUTHREQ_BIT) {
      this.handleScPairingRequest(data);
    } else {
      this.handleLegacyPairingRequest(data);
    }
  }

  validatePairingRequest(data) {
    if (!Buffer.isBuffer(data) ||
        data.length !== 7 ||
        data[0] !== SMP_PAIRING_REQUEST) {
      return SMP_INVALID_PARAMETERS;
    }

    if (data[1] > 0x04 ||
        data[2] > 0x01 ||
        (data[3] & 0x03) > 0x01 ||
        (data[3] & 0xc0) !== 0 ||
        (data[5] & 0xf0) !== 0 ||
        (data[6] & 0xf0) !== 0) {
      return SMP_INVALID_PARAMETERS;
    }

    if (data[4] < 7) {
      return SMP_ENCRYPTION_KEY_SIZE;
    }

    if (data[4] > 16) {
      return SMP_INVALID_PARAMETERS;
    }

    if (data[3] & SC_AUTHREQ_BIT) {
      if (data[2] !== 0) {
        return SMP_OOB_NOT_AVAILABLE;
      }
    }

    return null;
  }

  handleScPairingRequest(data) {
    this.resetScKeyExchange();
    this.resetLegacyPairing();
    this._pairingMode = PAIRING_MODE_SC;
    this._pairingStage = PAIRING_STAGE_IDLE;
    this._pairingTimedOut = false;
    this._preq = Buffer.from(data);
    this._pres = Buffer.from([
      SMP_PAIRING_RESPONSE,
      0x03, // IO capability: NoInputNoOutput
      0x00, // OOB data: Authentication data not present
      0x08, // Secure Connections, no MITM, no bonding
      0x10, // Max encryption key size
      0x00, // Initiator key distribution: <none>
      0x00  // Responder key distribution: <none>
    ]);

    this.startPairingTimer();

    try {
      this.startScKeyExchange();
      this.writeScPdu(this._pres);
      this._pairingStage = PAIRING_STAGE_FEATURES_EXCHANGED;
    } catch (error) {
      this.failScPairing(SMP_UNSPECIFIED);
    }
  }

  handleLegacyPairingRequest(data) {
    this.resetScKeyExchange();
    this.resetLegacyPairing();
    this._pairingMode = PAIRING_MODE_LEGACY;
    this._pairingStage = PAIRING_STAGE_FEATURES_EXCHANGED;
    this._preq = Buffer.from(data);

    this._pres = Buffer.from([
      SMP_PAIRING_RESPONSE,
      0x03, // IO capability: NoInputNoOutput
      0x00, // OOB data: Authentication data not present
      0x01, // Authentication requirement: Bonding - No MITM
      0x10, // Max encryption key size
      0x00, // Initiator key distribution: <none>
      0x01  // Responder key distribution: EncKey
    ]);

    try {
      this.write(this._pres);
    } catch (error) {
      this.failLegacyPairing(SMP_UNSPECIFIED);
    }
  }

  handleScPublicKey(data) {
    if (this._pairingStage !==
        PAIRING_STAGE_FEATURES_EXCHANGED) {
      this.failScPairing(SMP_INVALID_PARAMETERS);
      return;
    }

    if (!Buffer.isBuffer(data) ||
        data.length !== 65 ||
        data[0] !== SMP_PAIRING_PUBLIC_KEY) {
      this.failScPairing(SMP_INVALID_PARAMETERS);
      return;
    }

    try {
      this.processScPublicKeyPdu(data);
      this._pairingStage = PAIRING_STAGE_PEER_PUBLIC_KEY;
    } catch (error) {
      this.failScPairing(SMP_DHKEY_CHECK_FAILED);
      return;
    }

    try {
      this.writeScPdu(this.buildScPublicKeyPdu());
      this.startScConfirmRandom();
      this.writeScPdu(this.buildScConfirmPdu(), true);
      this._pairingStage = PAIRING_STAGE_LOCAL_CONFIRM;
    } catch (error) {
      this.failScPairing(SMP_UNSPECIFIED);
    }
  }

  handleScRandom(data) {
    if (this._pairingStage !== PAIRING_STAGE_LOCAL_CONFIRM) {
      this.failScPairing(SMP_INVALID_PARAMETERS);
      return;
    }

    if (!Buffer.isBuffer(data) ||
        data.length !== 17 ||
        data[0] !== SMP_PAIRING_RANDOM) {
      this.failScPairing(SMP_INVALID_PARAMETERS);
      return;
    }

    try {
      this.processScRandomPdu(data);
      this._pairingStage = PAIRING_STAGE_PEER_RANDOM;
    } catch (error) {
      this.failScPairing(SMP_INVALID_PARAMETERS);
      return;
    }

    try {
      this.writeScPdu(this.buildScRandomPdu(), true);
      this._pairingStage = PAIRING_STAGE_LOCAL_RANDOM;
      this.deriveScKeyMaterial(this._preq, this._pres);
    } catch (error) {
      this.failScPairing(SMP_UNSPECIFIED);
    }
  }

  handleScDhKeyCheck(data) {
    if (this._pairingStage !== PAIRING_STAGE_LOCAL_RANDOM) {
      this.failScPairing(SMP_INVALID_PARAMETERS);
      return;
    }

    if (!Buffer.isBuffer(data) ||
        data.length !== 17 ||
        data[0] !== SMP_PAIRING_DHKEY_CHECK) {
      this.failScPairing(SMP_INVALID_PARAMETERS);
      return;
    }

    try {
      this.processScDhKeyCheckPdu(data);
      this._pairingStage = PAIRING_STAGE_PEER_DHKEY_CHECK;
    } catch (error) {
      this.failScPairing(SMP_DHKEY_CHECK_FAILED);
      return;
    }

    try {
      const localCheck = this.buildScDhKeyCheckPdu();

      this.writeScPdu(localCheck, true);
      this._pairingStage = PAIRING_STAGE_LOCAL_DHKEY_CHECK;
      this.handoffScEncryptionMaterial();
      this._pairingStage = PAIRING_STAGE_ENCRYPTION_MATERIAL;
      this._pairingStage = PAIRING_STAGE_WAITING_FOR_ENCRYPTION;
    } catch (error) {
      this.failScPairing(SMP_UNSPECIFIED);
    }
  }

  writeScPdu(data, sensitive) {
    try {
      // AclStream copies the PDU into its HCI queue before returning.
      this.write(data);
    } finally {
      if (sensitive) {
        data.fill(0);
      }
    }

    this.restartPairingTimer();
  }

  startPairingTimer() {
    this.restartPairingTimer();
  }

  restartPairingTimer() {
    this.clearPairingTimer();

    if (this._pairingMode !== PAIRING_MODE_SC ||
        this._pairingFailed ||
        this._pairingTimedOut) {
      return;
    }

    this._pairingTimer = setTimeout(() => {
      this.onPairingTimeout();
    }, SC_PAIRING_TIMEOUT_MS);

    if (this._pairingTimer.unref) {
      this._pairingTimer.unref();
    }
  }

  clearPairingTimer() {
    if (!this._pairingTimer) {
      return;
    }

    clearTimeout(this._pairingTimer);
    this._pairingTimer = null;
  }

  onPairingTimeout() {
    if (this._pairingMode !== PAIRING_MODE_SC ||
        this._pairingFailed ||
        this._pairingTimedOut) {
      return;
    }

    this._pairingTimedOut = true;
    this._pairingFailed = true;
    this.clearPairingTimer();
    this.resetScKeyExchange();
    this.resetLegacyPairing();
    this._pairingMode = PAIRING_MODE_NONE;
    this._pairingStage = PAIRING_STAGE_IDLE;
    this.emit('fail');
  }

  failPairingBeforeMode(reason) {
    if (this._pairingFailed) {
      return;
    }

    this._pairingFailed = true;
    this.sendPairingFailed(reason);
    this.resetScKeyExchange();
    this.resetLegacyPairing();
    this.emit('fail');
  }

  failScPairing(reason) {
    if (this._pairingFailed) {
      return;
    }

    this._pairingFailed = true;
    this.clearPairingTimer();
    this.sendPairingFailed(reason);
    this.resetScKeyExchange();
    this.resetLegacyPairing();
    this._pairingMode = PAIRING_MODE_NONE;
    this._pairingStage = PAIRING_STAGE_IDLE;
    this.emit('fail');
  }

  failLegacyPairing(reason) {
    if (this._pairingFailed) {
      return;
    }

    this._pairingFailed = true;
    this.sendPairingFailed(reason);
    this.resetScKeyExchange();
    this.resetLegacyPairing();
    this._pairingMode = PAIRING_MODE_NONE;
    this._pairingStage = PAIRING_STAGE_IDLE;
    this.emit('fail');
  }

  sendPairingFailed(reason) {
    try {
      this.write(Buffer.from([
        SMP_PAIRING_FAILED,
        reason
      ]));
    } catch (error) {
      // Pairing state is still cleared by the caller.
    }
  }

  finishPairingAttempt() {
    this.clearPairingTimer();
    this._pairingMode = PAIRING_MODE_NONE;
    this._pairingStage = PAIRING_STAGE_IDLE;
    this._pairingFailed = false;
    this._pairingTimedOut = false;
  }

  resetLegacyPairing() {
    [
      '_preq',
      '_pres',
      '_pcnf',
      '_tk',
      '_r',
      '_stk',
      '_random',
      '_diversifier'
    ].forEach((field) => {
      if (this[field]) {
        this[field].fill(0);
        this[field] = null;
      }
    });
  }

  handlePairingConfirm(data) {
    this._pcnf = Buffer.from(data);

    this._tk = Buffer.from('00000000000000000000000000000000', 'hex');
    this._r = crypto.r();

    this.write(Buffer.concat([
      Buffer.from([SMP_PAIRING_CONFIRM]),
      crypto.c1(this._tk, this._r, this._pres, this._preq, this._iat, this._ia, this._rat, this._ra)
    ]));
  }

  handlePairingRandom(data) {
    const r = data.slice(1);

    const pcnf = Buffer.concat([
      Buffer.from([SMP_PAIRING_CONFIRM]),
      crypto.c1(this._tk, r, this._pres, this._preq, this._iat, this._ia, this._rat, this._ra)
    ]);

    if (this._pcnf.toString('hex') === pcnf.toString('hex')) {
      this._diversifier = Buffer.from('0000', 'hex');
      this._random = Buffer.from('0000000000000000', 'hex');
      this._stk = crypto.s1(this._tk, this._r, r);

      mgmt.addLongTermKey(this._ia, this._iat, 0, 0, this._diversifier, this._random, this._stk);

      this.write(Buffer.concat([
        Buffer.from([SMP_PAIRING_RANDOM]),
        this._r
      ]));
    } else {
      this.failLegacyPairing(SMP_PAIRING_CONFIRM);
    }
  }

  handlePairingFailed(data) {
    if (!Buffer.isBuffer(data) || data.length !== 2) {
      if (this._pairingMode === PAIRING_MODE_SC) {
        this.failScPairing(SMP_INVALID_PARAMETERS);
      }

      return;
    }

    if (this._pairingFailed) {
      return;
    }

    this._pairingFailed = true;
    this.clearPairingTimer();
    this.resetScKeyExchange();
    this.resetLegacyPairing();
    this._pairingMode = PAIRING_MODE_NONE;
    this._pairingStage = PAIRING_STAGE_IDLE;
    this.emit('fail');
  }

  // privateKey is supplied only by deterministic tests; runtime omits it.
  startScKeyExchange(privateKey) {
    let keyPair;

    this.resetScKeyExchange();

    try {
      keyPair = crypto.generateP256KeyPair(privateKey);
      this._scKeyExchange = {
        localPrivateKey: keyPair.privateKey,
        localPublicKey: keyPair.publicKey,
        peerPublicKey: null,
        dhKey: null,
        localNonce: null,
        peerNonce: null,
        localConfirm: null,
        macKey: null,
        ltk: null,
        localDhKeyCheck: null,
        expectedPeerDhKeyCheck: null,
        keySize: 0,
        confirmRandomStage: SC_STAGE_KEY_EXCHANGE_PENDING
      };
      keyPair = null;
    } catch (error) {
      if (keyPair && keyPair.privateKey) {
        keyPair.privateKey.fill(0);
      }

      this.resetScKeyExchange();
      throw error;
    }
  }

  buildScPublicKeyPdu() {
    try {
      if (!this._scKeyExchange) {
        throw new Error('SC key exchange context is not initialized');
      }

      return buildPairingPublicKeyPdu(
        this._scKeyExchange.localPublicKey
      );
    } catch (error) {
      this.resetScKeyExchange();
      throw error;
    }
  }

  processScPublicKeyPdu(pdu) {
    let dhKey;

    try {
      if (!this._scKeyExchange) {
        throw new Error('SC key exchange context is not initialized');
      }

      if (this._scKeyExchange.peerPublicKey) {
        throw new Error('peer public key has already been processed');
      }

      const peerPublicKey = parsePairingPublicKeyPdu(pdu);

      if (!crypto.validateP256PublicKey(peerPublicKey)) {
        throw new Error('peer public key is not on P-256');
      }

      const sameX = this._scKeyExchange.localPublicKey
        .slice(0, 32)
        .equals(peerPublicKey.slice(0, 32));
      const localDebugKey = this._scKeyExchange.localPublicKey
        .equals(SC_DEBUG_PUBLIC_KEY);
      const peerDebugKey = peerPublicKey.equals(SC_DEBUG_PUBLIC_KEY);

      if (sameX && !localDebugKey && !peerDebugKey) {
        throw new Error('peer public key matches the local public key');
      }

      dhKey = crypto.computeP256DhKey(
        this._scKeyExchange.localPrivateKey,
        peerPublicKey
      );

      this._scKeyExchange.peerPublicKey = Buffer.from(peerPublicKey);
      this._scKeyExchange.dhKey = Buffer.from(dhKey);
      this._scKeyExchange.confirmRandomStage =
        SC_STAGE_KEY_EXCHANGE_COMPLETE;
      dhKey.fill(0);
      dhKey = null;
    } catch (error) {
      if (dhKey) {
        dhKey.fill(0);
      }

      this.resetScKeyExchange();
      throw error;
    }
  }

  // localNonce is supplied only by deterministic tests; runtime omits it.
  startScConfirmRandom(localNonce) {
    let nonce;

    try {
      if (!this._scKeyExchange ||
          this._scKeyExchange.confirmRandomStage !==
            SC_STAGE_KEY_EXCHANGE_COMPLETE) {
        throw new Error('SC key exchange is not complete');
      }

      if (localNonce === undefined) {
        nonce = crypto.r();
      } else {
        assertLength(localNonce, 16, 'localNonce');
        nonce = Buffer.from(localNonce);
      }

      assertLength(nonce, 16, 'localNonce');
      this._scKeyExchange.localNonce = nonce;
      nonce = null;
      this._scKeyExchange.localConfirm = crypto.f4(
        this._scKeyExchange.localPublicKey.slice(0, 32),
        this._scKeyExchange.peerPublicKey.slice(0, 32),
        this._scKeyExchange.localNonce,
        Buffer.from([0x00])
      );
      this._scKeyExchange.confirmRandomStage =
        SC_STAGE_LOCAL_CONFIRM_READY;
    } catch (error) {
      if (nonce) {
        nonce.fill(0);
      }

      this.resetScKeyExchange();
      throw error;
    }
  }

  buildScConfirmPdu() {
    try {
      if (!this._scKeyExchange ||
          this._scKeyExchange.confirmRandomStage !==
            SC_STAGE_LOCAL_CONFIRM_READY) {
        throw new Error('local SC confirm is not ready');
      }

      const pdu = buildPairingConfirmPdu(
        this._scKeyExchange.localConfirm
      );

      this._scKeyExchange.confirmRandomStage =
        SC_STAGE_LOCAL_CONFIRM_BUILT;

      return pdu;
    } catch (error) {
      this.resetScKeyExchange();
      throw error;
    }
  }

  processScRandomPdu(pdu) {
    let peerNonce;

    try {
      if (!this._scKeyExchange ||
          this._scKeyExchange.confirmRandomStage !==
            SC_STAGE_LOCAL_CONFIRM_BUILT) {
        throw new Error('peer SC random is not expected');
      }

      peerNonce = parsePairingRandomPdu(pdu);
      this._scKeyExchange.peerNonce = Buffer.from(peerNonce);
      peerNonce.fill(0);
      peerNonce = null;
      this._scKeyExchange.confirmRandomStage =
        SC_STAGE_PEER_RANDOM_RECEIVED;
    } catch (error) {
      if (peerNonce) {
        peerNonce.fill(0);
      }

      this.resetScKeyExchange();
      throw error;
    }
  }

  buildScRandomPdu() {
    try {
      if (!this._scKeyExchange ||
          this._scKeyExchange.confirmRandomStage !==
            SC_STAGE_PEER_RANDOM_RECEIVED) {
        throw new Error('local SC random is not ready');
      }

      const pdu = buildPairingRandomPdu(
        this._scKeyExchange.localNonce
      );

      this._scKeyExchange.confirmRandomStage =
        SC_STAGE_CONFIRM_RANDOM_COMPLETE;

      return pdu;
    } catch (error) {
      this.resetScKeyExchange();
      throw error;
    }
  }

  deriveScKeyMaterial(pairingRequest, pairingResponse) {
    let keyMaterial;
    let expectedPeerDhKeyCheck;
    let localDhKeyCheck;
    let initiatorAddress;
    let responderAddress;
    let initiatorIoCap;
    let responderIoCap;
    let zeroR;
    let negotiatedKeySize;

    try {
      if (!this._scKeyExchange ||
          this._scKeyExchange.confirmRandomStage !==
            SC_STAGE_CONFIRM_RANDOM_COMPLETE) {
        throw new Error('SC Confirm and Random is not complete');
      }

      initiatorAddress = buildScAddress(this._iat, this._ia);
      responderAddress = buildScAddress(this._rat, this._ra);
      initiatorIoCap = buildScIoCap(
        pairingRequest,
        SMP_PAIRING_REQUEST,
        'pairingRequest'
      );
      responderIoCap = buildScIoCap(
        pairingResponse,
        SMP_PAIRING_RESPONSE,
        'pairingResponse'
      );
      negotiatedKeySize = getNegotiatedScKeySize(
        pairingRequest,
        pairingResponse
      );
      zeroR = Buffer.alloc(16);

      keyMaterial = crypto.f5(
        this._scKeyExchange.dhKey,
        this._scKeyExchange.peerNonce,
        this._scKeyExchange.localNonce,
        initiatorAddress,
        responderAddress
      );
      expectedPeerDhKeyCheck = crypto.f6(
        keyMaterial.macKey,
        this._scKeyExchange.peerNonce,
        this._scKeyExchange.localNonce,
        zeroR,
        initiatorIoCap,
        initiatorAddress,
        responderAddress
      );
      localDhKeyCheck = crypto.f6(
        keyMaterial.macKey,
        this._scKeyExchange.localNonce,
        this._scKeyExchange.peerNonce,
        zeroR,
        responderIoCap,
        responderAddress,
        initiatorAddress
      );

      // SC values stay MSO-first internally; mask the MSO octets.
      keyMaterial.ltk.fill(0, 0, 16 - negotiatedKeySize);

      this._scKeyExchange.macKey = keyMaterial.macKey;
      this._scKeyExchange.ltk = keyMaterial.ltk;
      this._scKeyExchange.expectedPeerDhKeyCheck =
        expectedPeerDhKeyCheck;
      this._scKeyExchange.localDhKeyCheck = localDhKeyCheck;
      this._scKeyExchange.keySize = negotiatedKeySize;
      this._scKeyExchange.confirmRandomStage =
        SC_STAGE_DHKEY_MATERIAL_READY;

      keyMaterial = null;
      expectedPeerDhKeyCheck = null;
      localDhKeyCheck = null;
    } catch (error) {
      if (keyMaterial) {
        keyMaterial.macKey.fill(0);
        keyMaterial.ltk.fill(0);
      }
      if (expectedPeerDhKeyCheck) {
        expectedPeerDhKeyCheck.fill(0);
      }
      if (localDhKeyCheck) {
        localDhKeyCheck.fill(0);
      }

      this.resetScKeyExchange();
      throw error;
    } finally {
      if (initiatorAddress) {
        initiatorAddress.fill(0);
      }
      if (responderAddress) {
        responderAddress.fill(0);
      }
      if (initiatorIoCap) {
        initiatorIoCap.fill(0);
      }
      if (responderIoCap) {
        responderIoCap.fill(0);
      }
      if (zeroR) {
        zeroR.fill(0);
      }
    }
  }

  processScDhKeyCheckPdu(pdu) {
    let peerDhKeyCheck;

    try {
      if (!this._scKeyExchange ||
          this._scKeyExchange.confirmRandomStage !==
            SC_STAGE_DHKEY_MATERIAL_READY) {
        throw new Error('peer SC DHKey Check is not expected');
      }

      peerDhKeyCheck = parsePairingDhKeyCheckPdu(pdu);

      if (!nodeCrypto.timingSafeEqual(
        peerDhKeyCheck,
        this._scKeyExchange.expectedPeerDhKeyCheck
      )) {
        throw new Error('peer SC DHKey Check does not match');
      }

      this._scKeyExchange.expectedPeerDhKeyCheck.fill(0);
      this._scKeyExchange.expectedPeerDhKeyCheck = null;
      this._scKeyExchange.confirmRandomStage =
        SC_STAGE_PEER_DHKEY_CHECK_VERIFIED;
    } catch (error) {
      this.resetScKeyExchange();
      throw error;
    } finally {
      if (peerDhKeyCheck) {
        peerDhKeyCheck.fill(0);
      }
    }
  }

  buildScDhKeyCheckPdu() {
    try {
      if (!this._scKeyExchange ||
          this._scKeyExchange.confirmRandomStage !==
            SC_STAGE_PEER_DHKEY_CHECK_VERIFIED) {
        throw new Error('local SC DHKey Check is not ready');
      }

      const pdu = buildPairingDhKeyCheckPdu(
        this._scKeyExchange.localDhKeyCheck
      );

      this._scKeyExchange.confirmRandomStage =
        SC_STAGE_DHKEY_CHECK_COMPLETE;

      return pdu;
    } catch (error) {
      this.resetScKeyExchange();
      throw error;
    }
  }

  handoffScEncryptionMaterial() {
    let transferLtk;

    try {
      if (!this._scKeyExchange ||
          this._scKeyExchange.confirmRandomStage !==
            SC_STAGE_DHKEY_CHECK_COMPLETE) {
        throw new Error('SC encryption material is not ready');
      }

      assertLength(this._scKeyExchange.ltk, 16, 'ltk');
      transferLtk = Buffer.from(this._scKeyExchange.ltk);

      this._aclStream.setPendingScEncryptionMaterial({
        ltk: transferLtk,
        secureConnections: true,
        authenticated: false,
        bonded: false,
        keySize: this._scKeyExchange.keySize
      });

      this._scKeyExchange.ltk.fill(0);
      this._scKeyExchange.ltk = null;
      this._scKeyExchange.confirmRandomStage =
        SC_STAGE_LTK_HANDED_OFF;
    } catch (error) {
      this.resetScKeyExchange();
      throw error;
    } finally {
      if (transferLtk) {
        transferLtk.fill(0);
      }
    }
  }

  resetScKeyExchange() {
    if (this._aclStream &&
        typeof this._aclStream.clearPendingScEncryptionMaterial ===
          'function') {
      this._aclStream.clearPendingScEncryptionMaterial();
    }

    if (!this._scKeyExchange) {
      return;
    }

    if (this._scKeyExchange.localPrivateKey) {
      this._scKeyExchange.localPrivateKey.fill(0);
    }

    if (this._scKeyExchange.dhKey) {
      this._scKeyExchange.dhKey.fill(0);
    }

    if (this._scKeyExchange.localNonce) {
      this._scKeyExchange.localNonce.fill(0);
    }

    if (this._scKeyExchange.peerNonce) {
      this._scKeyExchange.peerNonce.fill(0);
    }

    if (this._scKeyExchange.localConfirm) {
      this._scKeyExchange.localConfirm.fill(0);
    }

    if (this._scKeyExchange.macKey) {
      this._scKeyExchange.macKey.fill(0);
    }

    if (this._scKeyExchange.ltk) {
      this._scKeyExchange.ltk.fill(0);
    }

    if (this._scKeyExchange.localDhKeyCheck) {
      this._scKeyExchange.localDhKeyCheck.fill(0);
    }

    if (this._scKeyExchange.expectedPeerDhKeyCheck) {
      this._scKeyExchange.expectedPeerDhKeyCheck.fill(0);
    }

    this._scKeyExchange = null;
  }

  write(data) {
    this._aclStream.write(SMP_CID, data);
  }
}

Smp.msoToSmp = msoToSmp;
Smp.smpToMso = smpToMso;
Smp.p256PublicKeyMsoToSmp = p256PublicKeyMsoToSmp;
Smp.p256PublicKeySmpToMso = p256PublicKeySmpToMso;
Smp.buildPairingPublicKeyPdu = buildPairingPublicKeyPdu;
Smp.parsePairingPublicKeyPdu = parsePairingPublicKeyPdu;
Smp.buildPairingDhKeyCheckPdu = buildPairingDhKeyCheckPdu;
Smp.parsePairingDhKeyCheckPdu = parsePairingDhKeyCheckPdu;
Smp.buildPairingConfirmPdu = buildPairingConfirmPdu;
Smp.parsePairingConfirmPdu = parsePairingConfirmPdu;
Smp.buildPairingRandomPdu = buildPairingRandomPdu;
Smp.parsePairingRandomPdu = parsePairingRandomPdu;

module.exports = Smp;
