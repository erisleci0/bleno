/* jshint mocha: true */

const assert = require('assert');
const nodeCrypto = require('crypto');
const { EventEmitter } = require('events');

const bluetoothCrypto = require('../lib/hci-socket/crypto');

const smpPath = require.resolve('../lib/hci-socket/smp');
const mgmtPath = require.resolve('../lib/hci-socket/mgmt');
const cachedSmp = require.cache[smpPath];
const cachedMgmt = require.cache[mgmtPath];
const mgmtCalls = [];

delete require.cache[smpPath];
require.cache[mgmtPath] = {
  id: mgmtPath,
  filename: mgmtPath,
  loaded: true,
  exports: {
    addLongTermKey: function() {
      mgmtCalls.push(Array.prototype.slice.call(arguments));
    }
  }
};

const Smp = require(smpPath);

if (cachedMgmt) {
  require.cache[mgmtPath] = cachedMgmt;
} else {
  delete require.cache[mgmtPath];
}

if (cachedSmp) {
  require.cache[smpPath] = cachedSmp;
} else {
  delete require.cache[smpPath];
}

function hex(value) {
  return Buffer.from(value.replace(/\s/g, ''), 'hex');
}

function createSmp(options) {
  options = options || {};

  const aclStream = new EventEmitter();

  aclStream.writes = [];
  aclStream.writeFailureIndex = null;
  aclStream.pendingSetCount = 0;
  aclStream.write = function(cid, data) {
    if (this.writeFailureIndex === this.writes.length) {
      throw new Error('ACL write failed');
    }

    this.writes.push({
      cid,
      data: Buffer.from(data)
    });
  };
  aclStream.pendingScEncryptionMaterial = null;
  aclStream.setPendingScEncryptionMaterial = function(material) {
    if (this.pendingScEncryptionMaterial) {
      throw new Error('SC encryption material is already pending');
    }

    this.pendingSetCount++;
    this.pendingScEncryptionMaterial = {
      ltk: Buffer.from(material.ltk),
      secureConnections: material.secureConnections,
      authenticated: material.authenticated,
      bonded: material.bonded,
      keySize: material.keySize
    };
  };
  aclStream.clearPendingScEncryptionMaterial = function() {
    if (!this.pendingScEncryptionMaterial) {
      return;
    }

    if (this.pendingScEncryptionMaterial.ltk) {
      this.pendingScEncryptionMaterial.ltk.fill(0);
    }

    this.pendingScEncryptionMaterial = null;
  };

  return {
    aclStream,
    smp: new Smp(
      aclStream,
      options.localAddressType || 'public',
      options.localAddress || '00:11:22:33:44:55',
      options.remoteAddressType || 'public',
      options.remoteAddress || 'aa:bb:cc:dd:ee:ff'
    )
  };
}

function assertZeroed(value) {
  assert.strictEqual(value.equals(Buffer.alloc(value.length)), true);
}

describe('HCI socket SMP wire format', function() {
  const value16 = hex('000102030405060708090a0b0c0d0e0f');
  const value16Smp = hex('0f0e0d0c0b0a09080706050403020100');
  const x = hex(
    '000102030405060708090a0b0c0d0e0f' +
    '101112131415161718191a1b1c1d1e1f'
  );
  const xSmp = hex(
    '1f1e1d1c1b1a19181716151413121110' +
    '0f0e0d0c0b0a09080706050403020100'
  );
  const y = hex(
    '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f'
  );
  const ySmp = hex(
    '9f9e9d9c9b9a99989796959493929190' +
    '8f8e8d8c8b8a89888786858483828180'
  );
  const publicKey = Buffer.concat([x, y]);
  const publicKeySmp = Buffer.concat([xSmp, ySmp]);

  it('should convert a 16-byte value in both directions', function() {
    assert.deepStrictEqual(Smp.msoToSmp(value16), value16Smp);
    assert.deepStrictEqual(Smp.smpToMso(value16Smp), value16);
  });

  it('should convert a 32-byte value in both directions', function() {
    assert.deepStrictEqual(Smp.msoToSmp(x), xSmp);
    assert.deepStrictEqual(Smp.smpToMso(xSmp), x);
  });

  it('should convert P-256 coordinates separately', function() {
    assert.deepStrictEqual(
      Smp.p256PublicKeyMsoToSmp(publicKey),
      publicKeySmp
    );
    assert.deepStrictEqual(
      Smp.p256PublicKeySmpToMso(publicKeySmp),
      publicKey
    );
  });

  it('should round-trip values without changing their byte order', function() {
    assert.deepStrictEqual(
      Smp.smpToMso(Smp.msoToSmp(value16)),
      value16
    );
    assert.deepStrictEqual(
      Smp.smpToMso(Smp.msoToSmp(x)),
      x
    );
    assert.deepStrictEqual(
      Smp.p256PublicKeySmpToMso(
        Smp.p256PublicKeyMsoToSmp(publicKey)
      ),
      publicKey
    );
  });

  it('should build and parse a Pairing Public Key PDU', function() {
    const pdu = Smp.buildPairingPublicKeyPdu(publicKey);

    assert.strictEqual(pdu.length, 65);
    assert.strictEqual(pdu[0], 0x0c);
    assert.deepStrictEqual(pdu.slice(1), publicKeySmp);
    assert.deepStrictEqual(Smp.parsePairingPublicKeyPdu(pdu), publicKey);
  });

  it('should build and parse a Pairing DHKey Check PDU', function() {
    const pdu = Smp.buildPairingDhKeyCheckPdu(value16);

    assert.strictEqual(pdu.length, 17);
    assert.strictEqual(pdu[0], 0x0d);
    assert.deepStrictEqual(pdu.slice(1), value16Smp);
    assert.deepStrictEqual(Smp.parsePairingDhKeyCheckPdu(pdu), value16);
  });

  it('should build and parse a Pairing Confirm PDU', function() {
    const pdu = Smp.buildPairingConfirmPdu(value16);

    assert.strictEqual(pdu.length, 17);
    assert.strictEqual(pdu[0], 0x03);
    assert.deepStrictEqual(pdu.slice(1), value16Smp);
    assert.deepStrictEqual(Smp.parsePairingConfirmPdu(pdu), value16);
  });

  it('should build and parse a Pairing Random PDU', function() {
    const pdu = Smp.buildPairingRandomPdu(value16);

    assert.strictEqual(pdu.length, 17);
    assert.strictEqual(pdu[0], 0x04);
    assert.deepStrictEqual(pdu.slice(1), value16Smp);
    assert.deepStrictEqual(Smp.parsePairingRandomPdu(pdu), value16);
  });

  it('should reject non-Buffer inputs', function() {
    [
      Smp.msoToSmp,
      Smp.smpToMso,
      Smp.p256PublicKeyMsoToSmp,
      Smp.p256PublicKeySmpToMso,
      Smp.buildPairingPublicKeyPdu,
      Smp.parsePairingPublicKeyPdu,
      Smp.buildPairingDhKeyCheckPdu,
      Smp.parsePairingDhKeyCheckPdu,
      Smp.buildPairingConfirmPdu,
      Smp.parsePairingConfirmPdu,
      Smp.buildPairingRandomPdu,
      Smp.parsePairingRandomPdu
    ].forEach(function(fn) {
      assert.throws(function() {
        fn('not a Buffer');
      }, TypeError);
    });
  });

  it('should reject invalid lengths', function() {
    [
      [Smp.msoToSmp, 15],
      [Smp.msoToSmp, 17],
      [Smp.smpToMso, 31],
      [Smp.smpToMso, 33],
      [Smp.p256PublicKeyMsoToSmp, 63],
      [Smp.p256PublicKeySmpToMso, 65],
      [Smp.buildPairingPublicKeyPdu, 63],
      [Smp.parsePairingPublicKeyPdu, 64],
      [Smp.parsePairingPublicKeyPdu, 66],
      [Smp.buildPairingDhKeyCheckPdu, 15],
      [Smp.buildPairingDhKeyCheckPdu, 17],
      [Smp.parsePairingDhKeyCheckPdu, 16],
      [Smp.parsePairingDhKeyCheckPdu, 18],
      [Smp.buildPairingConfirmPdu, 15],
      [Smp.buildPairingConfirmPdu, 17],
      [Smp.parsePairingConfirmPdu, 16],
      [Smp.parsePairingConfirmPdu, 18],
      [Smp.buildPairingRandomPdu, 15],
      [Smp.buildPairingRandomPdu, 17],
      [Smp.parsePairingRandomPdu, 16],
      [Smp.parsePairingRandomPdu, 18]
    ].forEach(function(testCase) {
      assert.throws(function() {
        testCase[0](Buffer.alloc(testCase[1]));
      }, RangeError);
    });
  });

  it('should reject invalid opcodes', function() {
    const publicKeyPdu = Buffer.concat([
      Buffer.from([0x0d]),
      publicKeySmp
    ]);
    const dhKeyCheckPdu = Buffer.concat([
      Buffer.from([0x0c]),
      value16Smp
    ]);
    const confirmPdu = Buffer.concat([
      Buffer.from([0x04]),
      value16Smp
    ]);
    const randomPdu = Buffer.concat([
      Buffer.from([0x03]),
      value16Smp
    ]);

    assert.throws(function() {
      Smp.parsePairingPublicKeyPdu(publicKeyPdu);
    }, RangeError);
    assert.throws(function() {
      Smp.parsePairingDhKeyCheckPdu(dhKeyCheckPdu);
    }, RangeError);
    assert.throws(function() {
      Smp.parsePairingConfirmPdu(confirmPdu);
    }, RangeError);
    assert.throws(function() {
      Smp.parsePairingRandomPdu(randomPdu);
    }, RangeError);
  });

  it('should not modify caller buffers', function() {
    const inputs = [
      Buffer.from(value16),
      Buffer.from(value16Smp),
      Buffer.from(x),
      Buffer.from(xSmp),
      Buffer.from(publicKey),
      Buffer.from(publicKeySmp)
    ];
    const originals = inputs.map(function(input) {
      return Buffer.from(input);
    });
    const publicKeyPdu = Smp.buildPairingPublicKeyPdu(inputs[4]);
    const dhKeyCheckPdu = Smp.buildPairingDhKeyCheckPdu(inputs[0]);
    const confirmPdu = Smp.buildPairingConfirmPdu(inputs[0]);
    const randomPdu = Smp.buildPairingRandomPdu(inputs[0]);
    const originalPublicKeyPdu = Buffer.from(publicKeyPdu);
    const originalDhKeyCheckPdu = Buffer.from(dhKeyCheckPdu);
    const originalConfirmPdu = Buffer.from(confirmPdu);
    const originalRandomPdu = Buffer.from(randomPdu);

    Smp.msoToSmp(inputs[0]);
    Smp.smpToMso(inputs[1]);
    Smp.msoToSmp(inputs[2]);
    Smp.smpToMso(inputs[3]);
    Smp.p256PublicKeyMsoToSmp(inputs[4]);
    Smp.p256PublicKeySmpToMso(inputs[5]);
    Smp.parsePairingPublicKeyPdu(publicKeyPdu);
    Smp.parsePairingDhKeyCheckPdu(dhKeyCheckPdu);
    Smp.parsePairingConfirmPdu(confirmPdu);
    Smp.parsePairingRandomPdu(randomPdu);

    inputs.forEach(function(input, index) {
      assert.deepStrictEqual(input, originals[index]);
    });
    assert.deepStrictEqual(publicKeyPdu, originalPublicKeyPdu);
    assert.deepStrictEqual(dhKeyCheckPdu, originalDhKeyCheckPdu);
    assert.deepStrictEqual(confirmPdu, originalConfirmPdu);
    assert.deepStrictEqual(randomPdu, originalRandomPdu);
  });
});

describe('HCI socket SMP ephemeral key exchange', function() {
  const privateA = hex(
    '3f49f6d4a3c55f3874c9b3e3d2103f50' +
    '4aff607beb40b7995899b8a6cd3c1abd'
  );
  const publicA = hex(
    '20b003d2f297be2c5e2c83a7e9f9a5b9' +
    'eff49111acf4fddbcc0301480e359de6' +
    'dc809c49652aeb6d63329abf5a52155c' +
    '766345c28fed3024741c8ed01589d28b'
  );
  const privateB = hex(
    '55188b3d32f6bb9a900afcfbeed4e72a' +
    '59cb9ac2f19d7cfb6b4fdd49f47fc5fd'
  );
  const publicB = hex(
    '1ea1f0f01faf1d9609592284f19e4c00' +
    '47b58afd8615a69f559077b22faaa190' +
    '4c55f33e429dad377356703a9ab85160' +
    '472d1130e28e36765f89aff915b1214a'
  );
  const expectedDhKey = hex(
    'ec0234a357c8ad05341010a60a397d9b' +
    '99796b13b4f866f1868d34f373bfa698'
  );
  const peerNonceA = hex('d5cb8454d177733effffb2ec712baeab');
  const localNonceB = hex('a6e8e7cc25a75f6e216583f7ff3dc4cf');
  const expectedMacKey =
    hex('2965f176a1084a02fd3f6a20ce636e20');
  const expectedLtk =
    hex('6986791169d7cd23980522b594750a38');
  const initiatorAddress = hex('0056123737bfce');
  const responderAddress = hex('00a713702dcfc1');
  const pairingRequest = Buffer.from([
    0x01,
    0x02, // IO capability
    0x00, // OOB data flag
    0x05, // AuthReq
    0x10,
    0x00,
    0x00
  ]);
  const pairingResponse = Buffer.from([
    0x02,
    0x03, // IO capability
    0x00, // OOB data flag
    0x01, // AuthReq
    0x10,
    0x00,
    0x00
  ]);
  const officialAddressOptions = {
    localAddressType: 'public',
    localAddress: 'a7:13:70:2d:cf:c1',
    remoteAddressType: 'public',
    remoteAddress: '56:12:37:37:bf:ce'
  };
  let connections;

  beforeEach(function() {
    connections = [];
  });

  afterEach(function() {
    connections.forEach(function(connection) {
      connection.aclStream.emit('end');
    });
  });

  function newConnection(options) {
    const connection = createSmp(options);
    connections.push(connection);
    return connection;
  }

  function completeKeyExchange(connection, localPrivateKey, peerPublicKey) {
    connection.smp.startScKeyExchange(localPrivateKey);
    connection.smp.processScPublicKeyPdu(
      Smp.buildPairingPublicKeyPdu(peerPublicKey)
    );
  }

  function completeConfirmRandom(connection) {
    completeKeyExchange(connection, privateB, publicA);
    connection.smp.startScConfirmRandom(localNonceB);
    connection.smp.buildScConfirmPdu();
    connection.smp.processScRandomPdu(
      Smp.buildPairingRandomPdu(peerNonceA)
    );
    connection.smp.buildScRandomPdu();
  }

  function completeDhKeyMaterial(
    connection,
    request,
    response
  ) {
    completeConfirmRandom(connection);
    connection.smp.deriveScKeyMaterial(
      request || pairingRequest,
      response || pairingResponse
    );
  }

  function completeDhKeyCheck(connection, request, response) {
    completeDhKeyMaterial(connection, request, response);

    const peerPdu = Smp.buildPairingDhKeyCheckPdu(
      connection.smp._scKeyExchange.expectedPeerDhKeyCheck
    );

    connection.smp.processScDhKeyCheckPdu(peerPdu);
    connection.smp.buildScDhKeyCheckPdu();
  }

  it('should initialize with an empty context', function() {
    const connection = newConnection();

    assert.strictEqual(connection.smp._scKeyExchange, null);
    assert.strictEqual(connection.aclStream.writes.length, 0);
  });

  it('should generate a valid fresh local key pair', function() {
    const connection = newConnection();
    const result = connection.smp.startScKeyExchange();
    const firstPrivateKey =
      connection.smp._scKeyExchange.localPrivateKey;

    assert.strictEqual(result, undefined);
    assert.strictEqual(firstPrivateKey.length, 32);
    assert.strictEqual(
      connection.smp._scKeyExchange.localPublicKey.length,
      64
    );
    assert.strictEqual(
      bluetoothCrypto.validateP256PublicKey(
        connection.smp._scKeyExchange.localPublicKey
      ),
      true
    );
    assert.strictEqual(
      connection.smp._scKeyExchange.peerPublicKey,
      null
    );
    assert.strictEqual(connection.smp._scKeyExchange.dhKey, null);

    connection.smp.startScKeyExchange();

    assertZeroed(firstPrivateKey);
    assert.strictEqual(
      bluetoothCrypto.validateP256PublicKey(
        connection.smp._scKeyExchange.localPublicKey
      ),
      true
    );
  });

  it('should build a local Public Key PDU that round-trips', function() {
    const connection = newConnection();

    connection.smp.startScKeyExchange(privateA);

    const pdu = connection.smp.buildScPublicKeyPdu();

    assert.deepStrictEqual(Smp.parsePairingPublicKeyPdu(pdu), publicA);
    assert.strictEqual(connection.aclStream.writes.length, 0);
  });

  it('should validate peer keys and derive the same expected DHKey', function() {
    const connectionA = newConnection();
    const connectionB = newConnection();

    connectionA.smp.startScKeyExchange(privateA);
    connectionB.smp.startScKeyExchange(privateB);

    connectionA.smp.processScPublicKeyPdu(
      connectionB.smp.buildScPublicKeyPdu()
    );
    connectionB.smp.processScPublicKeyPdu(
      connectionA.smp.buildScPublicKeyPdu()
    );

    assert.deepStrictEqual(
      connectionA.smp._scKeyExchange.peerPublicKey,
      publicB
    );
    assert.deepStrictEqual(
      connectionB.smp._scKeyExchange.peerPublicKey,
      publicA
    );
    assert.strictEqual(
      connectionA.smp._scKeyExchange.dhKey.equals(expectedDhKey),
      true
    );
    assert.strictEqual(
      connectionB.smp._scKeyExchange.dhKey.equals(expectedDhKey),
      true
    );
    assert.strictEqual(
      connectionA.smp._scKeyExchange.dhKey.equals(
        connectionB.smp._scKeyExchange.dhKey
      ),
      true
    );
  });

  it('should reject invalid public-key types and lengths', function() {
    const connection = newConnection();

    connection.smp.startScKeyExchange(privateB);
    const firstPrivateKey =
      connection.smp._scKeyExchange.localPrivateKey;

    assert.throws(function() {
      connection.smp.processScPublicKeyPdu('not a Buffer');
    }, TypeError);
    assertZeroed(firstPrivateKey);
    assert.strictEqual(connection.smp._scKeyExchange, null);

    connection.smp.startScKeyExchange(privateB);
    const secondPrivateKey =
      connection.smp._scKeyExchange.localPrivateKey;

    assert.throws(function() {
      connection.smp.processScPublicKeyPdu(Buffer.alloc(64));
    }, RangeError);
    assertZeroed(secondPrivateKey);
    assert.strictEqual(connection.smp._scKeyExchange, null);

    connection.smp.startScKeyExchange(privateB);
    const thirdPrivateKey =
      connection.smp._scKeyExchange.localPrivateKey;
    const invalidOpcodePdu = Smp.buildPairingPublicKeyPdu(publicA);
    invalidOpcodePdu[0] = 0x0d;

    assert.throws(function() {
      connection.smp.processScPublicKeyPdu(invalidOpcodePdu);
    }, RangeError);
    assertZeroed(thirdPrivateKey);
    assert.strictEqual(connection.smp._scKeyExchange, null);
  });

  it('should reject an off-curve peer public key', function() {
    const connection = newConnection();

    connection.smp.startScKeyExchange(privateB);
    const privateKey = connection.smp._scKeyExchange.localPrivateKey;
    const pdu = Smp.buildPairingPublicKeyPdu(Buffer.alloc(64));

    assert.throws(function() {
      connection.smp.processScPublicKeyPdu(pdu);
    });
    assertZeroed(privateKey);
    assert.strictEqual(connection.smp._scKeyExchange, null);
  });

  it('should reject a duplicate Public Key PDU', function() {
    const connection = newConnection();
    const pdu = Smp.buildPairingPublicKeyPdu(publicB);

    connection.smp.startScKeyExchange(privateA);
    connection.smp.processScPublicKeyPdu(pdu);

    const privateKey = connection.smp._scKeyExchange.localPrivateKey;
    const dhKey = connection.smp._scKeyExchange.dhKey;

    assert.throws(function() {
      connection.smp.processScPublicKeyPdu(pdu);
    });
    assertZeroed(privateKey);
    assertZeroed(dhKey);
    assert.strictEqual(connection.smp._scKeyExchange, null);
  });

  it('should reject a matching non-debug public key', function() {
    const connection = newConnection();

    connection.smp.startScKeyExchange(privateB);
    const privateKey = connection.smp._scKeyExchange.localPrivateKey;

    assert.throws(function() {
      connection.smp.processScPublicKeyPdu(
        connection.smp.buildScPublicKeyPdu()
      );
    });
    assertZeroed(privateKey);
    assert.strictEqual(connection.smp._scKeyExchange, null);
  });

  it('should allow the matching Secure Connections debug key', function() {
    const connection = newConnection();

    connection.smp.startScKeyExchange(privateA);
    connection.smp.processScPublicKeyPdu(
      connection.smp.buildScPublicKeyPdu()
    );

    assert.deepStrictEqual(
      connection.smp._scKeyExchange.peerPublicKey,
      publicA
    );
    assert.strictEqual(connection.smp._scKeyExchange.dhKey.length, 32);
  });

  it('should reject processing without an initialized context', function() {
    const connection = newConnection();
    const pdu = Smp.buildPairingPublicKeyPdu(publicA);

    assert.throws(function() {
      connection.smp.buildScPublicKeyPdu();
    });
    assert.throws(function() {
      connection.smp.processScPublicKeyPdu(pdu);
    });
    assert.strictEqual(connection.smp._scKeyExchange, null);
  });

  it('should protect the context from caller mutation', function() {
    const connection = newConnection();
    const callerPrivateKey = Buffer.from(privateB);
    const originalPrivateKey = Buffer.from(callerPrivateKey);

    connection.smp.startScKeyExchange(callerPrivateKey);
    const localPdu = connection.smp.buildScPublicKeyPdu();

    callerPrivateKey.fill(0);
    localPdu.fill(0);

    assert.strictEqual(
      connection.smp._scKeyExchange.localPrivateKey.equals(
        originalPrivateKey
      ),
      true
    );
    assert.deepStrictEqual(
      connection.smp._scKeyExchange.localPublicKey,
      publicB
    );

    const peerPdu = Smp.buildPairingPublicKeyPdu(publicA);

    connection.smp.processScPublicKeyPdu(peerPdu);
    peerPdu.fill(0);

    assert.deepStrictEqual(
      connection.smp._scKeyExchange.peerPublicKey,
      publicA
    );
  });

  // Bluetooth Core Specification, Vol 3, Part H, Appendix D.2.
  it('should match the official f4 vector', function() {
    const result = bluetoothCrypto.f4(
      hex(
        '20b003d2f297be2c5e2c83a7e9f9a5b9' +
        'eff49111acf4fddbcc0301480e359de6'
      ),
      hex(
        '55188b3d32f6bb9a900afcfbeed4e72a' +
        '59cb9ac2f19d7cfb6b4fdd49f47fc5fd'
      ),
      peerNonceA,
      Buffer.from([0x00])
    );

    assert.strictEqual(
      result.equals(hex('f2c916f107a9bd1cf1eda1bea974872d')),
      true
    );
  });

  it('should generate a valid local nonce and responder confirm', function() {
    const connection = newConnection();

    completeKeyExchange(connection, privateB, publicA);
    connection.smp.startScConfirmRandom();

    const context = connection.smp._scKeyExchange;
    const expectedConfirm = bluetoothCrypto.f4(
      publicB.slice(0, 32),
      publicA.slice(0, 32),
      context.localNonce,
      Buffer.from([0x00])
    );

    assert.strictEqual(Buffer.isBuffer(context.localNonce), true);
    assert.strictEqual(context.localNonce.length, 16);
    assert.strictEqual(context.localConfirm.length, 16);
    assert.strictEqual(context.localConfirm.equals(expectedConfirm), true);
    assert.strictEqual(context.peerNonce, null);
    assert.strictEqual(
      context.confirmRandomStage,
      'localConfirmReady'
    );
  });

  it('should use PKbx, PKax, Nb, and zero for responder f4', function() {
    const connection = newConnection();
    const callerNonce = Buffer.from(localNonceB);
    const originalNonce = Buffer.from(callerNonce);

    completeKeyExchange(connection, privateB, publicA);
    connection.smp.startScConfirmRandom(callerNonce);

    const expectedConfirm = bluetoothCrypto.f4(
      publicB.slice(0, 32),
      publicA.slice(0, 32),
      localNonceB,
      Buffer.from([0x00])
    );

    assert.deepStrictEqual(callerNonce, originalNonce);
    assert.deepStrictEqual(
      connection.smp._scKeyExchange.localNonce,
      localNonceB
    );
    assert.strictEqual(
      connection.smp._scKeyExchange.localConfirm.equals(expectedConfirm),
      true
    );
  });

  it('should complete the responder Confirm and Random state order', function() {
    const connection = newConnection();

    completeKeyExchange(connection, privateB, publicA);
    assert.strictEqual(
      connection.smp._scKeyExchange.confirmRandomStage,
      'keyExchangeComplete'
    );

    connection.smp.startScConfirmRandom(localNonceB);
    const confirmPdu = connection.smp.buildScConfirmPdu();

    assert.deepStrictEqual(
      Smp.parsePairingConfirmPdu(confirmPdu),
      connection.smp._scKeyExchange.localConfirm
    );
    assert.strictEqual(
      connection.smp._scKeyExchange.confirmRandomStage,
      'localConfirmBuilt'
    );

    connection.smp.processScRandomPdu(
      Smp.buildPairingRandomPdu(peerNonceA)
    );

    assert.deepStrictEqual(
      connection.smp._scKeyExchange.peerNonce,
      peerNonceA
    );
    assert.strictEqual(
      connection.smp._scKeyExchange.confirmRandomStage,
      'peerRandomReceived'
    );

    const randomPdu = connection.smp.buildScRandomPdu();

    assert.deepStrictEqual(
      Smp.parsePairingRandomPdu(randomPdu),
      localNonceB
    );
    assert.strictEqual(
      connection.smp._scKeyExchange.confirmRandomStage,
      'confirmRandomComplete'
    );
  });

  it('should reject invalid nonce inputs and clear the context', function() {
    const connection = newConnection();

    completeKeyExchange(connection, privateB, publicA);
    const firstPrivateKey =
      connection.smp._scKeyExchange.localPrivateKey;
    const firstDhKey = connection.smp._scKeyExchange.dhKey;

    assert.throws(function() {
      connection.smp.startScConfirmRandom('not a Buffer');
    }, TypeError);
    assertZeroed(firstPrivateKey);
    assertZeroed(firstDhKey);
    assert.strictEqual(connection.smp._scKeyExchange, null);

    completeKeyExchange(connection, privateB, publicA);
    const secondPrivateKey =
      connection.smp._scKeyExchange.localPrivateKey;
    const secondDhKey = connection.smp._scKeyExchange.dhKey;

    assert.throws(function() {
      connection.smp.startScConfirmRandom(Buffer.alloc(15));
    }, RangeError);
    assertZeroed(secondPrivateKey);
    assertZeroed(secondDhKey);
    assert.strictEqual(connection.smp._scKeyExchange, null);
  });

  it('should reject missing context and out-of-order operations', function() {
    const withoutContext = newConnection();

    assert.throws(function() {
      withoutContext.smp.startScConfirmRandom(localNonceB);
    });

    const confirmBeforeStart = newConnection();
    completeKeyExchange(confirmBeforeStart, privateB, publicA);
    assert.throws(function() {
      confirmBeforeStart.smp.buildScConfirmPdu();
    });
    assert.strictEqual(confirmBeforeStart.smp._scKeyExchange, null);

    const randomBeforeConfirm = newConnection();
    completeKeyExchange(randomBeforeConfirm, privateB, publicA);
    randomBeforeConfirm.smp.startScConfirmRandom(localNonceB);
    assert.throws(function() {
      randomBeforeConfirm.smp.processScRandomPdu(
        Smp.buildPairingRandomPdu(peerNonceA)
      );
    });
    assert.strictEqual(randomBeforeConfirm.smp._scKeyExchange, null);

    const localRandomBeforePeer = newConnection();
    completeKeyExchange(localRandomBeforePeer, privateB, publicA);
    localRandomBeforePeer.smp.startScConfirmRandom(localNonceB);
    localRandomBeforePeer.smp.buildScConfirmPdu();
    assert.throws(function() {
      localRandomBeforePeer.smp.buildScRandomPdu();
    });
    assert.strictEqual(localRandomBeforePeer.smp._scKeyExchange, null);
  });

  it('should reject duplicate Confirm and Random operations', function() {
    const duplicateConfirm = newConnection();
    completeKeyExchange(duplicateConfirm, privateB, publicA);
    duplicateConfirm.smp.startScConfirmRandom(localNonceB);
    duplicateConfirm.smp.buildScConfirmPdu();
    assert.throws(function() {
      duplicateConfirm.smp.buildScConfirmPdu();
    });
    assert.strictEqual(duplicateConfirm.smp._scKeyExchange, null);

    const duplicatePeerRandom = newConnection();
    completeKeyExchange(duplicatePeerRandom, privateB, publicA);
    duplicatePeerRandom.smp.startScConfirmRandom(localNonceB);
    duplicatePeerRandom.smp.buildScConfirmPdu();
    const peerRandomPdu = Smp.buildPairingRandomPdu(peerNonceA);
    duplicatePeerRandom.smp.processScRandomPdu(peerRandomPdu);
    assert.throws(function() {
      duplicatePeerRandom.smp.processScRandomPdu(peerRandomPdu);
    });
    assert.strictEqual(duplicatePeerRandom.smp._scKeyExchange, null);

    const duplicateLocalRandom = newConnection();
    completeConfirmRandom(duplicateLocalRandom);
    assert.throws(function() {
      duplicateLocalRandom.smp.buildScRandomPdu();
    });
    assert.strictEqual(duplicateLocalRandom.smp._scKeyExchange, null);
  });

  it('should reject invalid Random PDUs and preserve caller buffers', function() {
    const connection = newConnection();
    const callerNonce = Buffer.from(localNonceB);
    const peerRandomPdu = Smp.buildPairingRandomPdu(peerNonceA);
    const originalPeerRandomPdu = Buffer.from(peerRandomPdu);

    completeKeyExchange(connection, privateB, publicA);
    connection.smp.startScConfirmRandom(callerNonce);
    const confirmPdu = connection.smp.buildScConfirmPdu();
    const originalConfirm = Buffer.from(
      connection.smp._scKeyExchange.localConfirm
    );

    connection.smp.processScRandomPdu(peerRandomPdu);
    const randomPdu = connection.smp.buildScRandomPdu();

    confirmPdu.fill(0);
    randomPdu.fill(0);

    assert.deepStrictEqual(callerNonce, localNonceB);
    assert.deepStrictEqual(peerRandomPdu, originalPeerRandomPdu);
    assert.deepStrictEqual(
      connection.smp._scKeyExchange.localConfirm,
      originalConfirm
    );
    assert.deepStrictEqual(
      connection.smp._scKeyExchange.localNonce,
      localNonceB
    );
    assert.deepStrictEqual(
      connection.smp._scKeyExchange.peerNonce,
      peerNonceA
    );

    connection.smp.resetScKeyExchange();
    completeKeyExchange(connection, privateB, publicA);
    connection.smp.startScConfirmRandom(localNonceB);
    connection.smp.buildScConfirmPdu();

    assert.throws(function() {
      connection.smp.processScRandomPdu(Buffer.alloc(16));
    }, RangeError);
    assert.strictEqual(connection.smp._scKeyExchange, null);
  });

  it('should clear the previous context when a new start fails', function() {
    const connection = newConnection();

    completeKeyExchange(connection, privateB, publicA);

    const privateKey = connection.smp._scKeyExchange.localPrivateKey;
    const dhKey = connection.smp._scKeyExchange.dhKey;

    assert.throws(function() {
      connection.smp.startScKeyExchange(Buffer.alloc(32));
    });

    assertZeroed(privateKey);
    assertZeroed(dhKey);
    assert.strictEqual(connection.smp._scKeyExchange, null);
  });

  it('should reset and clear all secrets after Confirm and Random', function() {
    const connection = newConnection();

    completeConfirmRandom(connection);

    const privateKey = connection.smp._scKeyExchange.localPrivateKey;
    const dhKey = connection.smp._scKeyExchange.dhKey;
    const localNonce = connection.smp._scKeyExchange.localNonce;
    const peerNonce = connection.smp._scKeyExchange.peerNonce;
    const localConfirm = connection.smp._scKeyExchange.localConfirm;

    connection.smp.resetScKeyExchange();

    assertZeroed(privateKey);
    assertZeroed(dhKey);
    assertZeroed(localNonce);
    assertZeroed(peerNonce);
    assertZeroed(localConfirm);
    assert.strictEqual(connection.smp._scKeyExchange, null);

    connection.smp.resetScKeyExchange();

    assert.strictEqual(connection.smp._scKeyExchange, null);
  });

  it('should reset and clear secrets after pairing failure', function() {
    const connection = newConnection();
    let failCount = 0;

    completeConfirmRandom(connection);

    const privateKey = connection.smp._scKeyExchange.localPrivateKey;
    const dhKey = connection.smp._scKeyExchange.dhKey;
    const localNonce = connection.smp._scKeyExchange.localNonce;
    const peerNonce = connection.smp._scKeyExchange.peerNonce;
    const localConfirm = connection.smp._scKeyExchange.localConfirm;

    connection.smp.on('fail', function() {
      failCount++;
    });
    connection.smp.handlePairingFailed(Buffer.from([0x05, 0x08]));

    assertZeroed(privateKey);
    assertZeroed(dhKey);
    assertZeroed(localNonce);
    assertZeroed(peerNonce);
    assertZeroed(localConfirm);
    assert.strictEqual(connection.smp._scKeyExchange, null);
    assert.strictEqual(failCount, 1);
  });

  it('should reset and clear secrets when the ACL stream ends', function() {
    const connection = newConnection();

    completeConfirmRandom(connection);

    const privateKey = connection.smp._scKeyExchange.localPrivateKey;
    const dhKey = connection.smp._scKeyExchange.dhKey;
    const localNonce = connection.smp._scKeyExchange.localNonce;
    const peerNonce = connection.smp._scKeyExchange.peerNonce;
    const localConfirm = connection.smp._scKeyExchange.localConfirm;

    connection.aclStream.emit('end');

    assertZeroed(privateKey);
    assertZeroed(dhKey);
    assertZeroed(localNonce);
    assertZeroed(peerNonce);
    assertZeroed(localConfirm);
    assert.strictEqual(connection.smp._scKeyExchange, null);
  });

  it('should not write any PDU to the live ACL stream', function() {
    const connectionA = newConnection();
    const connectionB = newConnection();

    connectionA.smp.startScKeyExchange(privateA);
    connectionB.smp.startScKeyExchange(privateB);
    connectionA.smp.processScPublicKeyPdu(
      connectionB.smp.buildScPublicKeyPdu()
    );
    connectionB.smp.processScPublicKeyPdu(
      connectionA.smp.buildScPublicKeyPdu()
    );
    connectionB.smp.startScConfirmRandom(localNonceB);
    connectionB.smp.buildScConfirmPdu();
    connectionB.smp.processScRandomPdu(
      Smp.buildPairingRandomPdu(peerNonceA)
    );
    connectionB.smp.buildScRandomPdu();

    assert.strictEqual(connectionA.aclStream.writes.length, 0);
    assert.strictEqual(connectionB.aclStream.writes.length, 0);
  });

  describe('DHKey Check foundation', function() {
    // Bluetooth Core Specification Amended 4.2,
    // Vol 3, Part H, Appendix D.3.
    it('should match the official f5 vector', function() {
      assert.deepStrictEqual(
        bluetoothCrypto.f5(
          expectedDhKey,
          peerNonceA,
          localNonceB,
          initiatorAddress,
          responderAddress
        ),
        {
          macKey: expectedMacKey,
          ltk: expectedLtk
        }
      );
    });

    // Bluetooth Core Specification Amended 4.2,
    // Vol 3, Part H, Appendix D.4.
    it('should match the official f6 vector', function() {
      assert.deepStrictEqual(
        bluetoothCrypto.f6(
          expectedMacKey,
          peerNonceA,
          localNonceB,
          hex('12a3343bb453bb5408da42d20c2d0fc8'),
          hex('010102'),
          initiatorAddress,
          responderAddress
        ),
        hex('e3c473989cd0e8c5d26c0b09da958f61')
      );
    });

    it('should derive responder MacKey, LTK, Ea, and Eb', function() {
      const connection = newConnection(officialAddressOptions);
      const callerRequest = Buffer.from(pairingRequest);
      const callerResponse = Buffer.from(pairingResponse);
      const originalRequest = Buffer.from(callerRequest);
      const originalResponse = Buffer.from(callerResponse);

      completeConfirmRandom(connection);
      connection.smp.deriveScKeyMaterial(
        callerRequest,
        callerResponse
      );

      const context = connection.smp._scKeyExchange;
      const zeroR = Buffer.alloc(16);
      const expectedEa = bluetoothCrypto.f6(
        expectedMacKey,
        peerNonceA,
        localNonceB,
        zeroR,
        hex('050002'),
        initiatorAddress,
        responderAddress
      );
      const expectedEb = bluetoothCrypto.f6(
        expectedMacKey,
        localNonceB,
        peerNonceA,
        zeroR,
        hex('010003'),
        responderAddress,
        initiatorAddress
      );

      assert.deepStrictEqual(context.macKey, expectedMacKey);
      assert.deepStrictEqual(context.ltk, expectedLtk);
      assert.strictEqual(context.keySize, 16);
      assert.deepStrictEqual(context.expectedPeerDhKeyCheck, expectedEa);
      assert.deepStrictEqual(context.localDhKeyCheck, expectedEb);
      assert.strictEqual(
        context.confirmRandomStage,
        'dhKeyMaterialReady'
      );
      assert.deepStrictEqual(callerRequest, originalRequest);
      assert.deepStrictEqual(callerResponse, originalResponse);
    });

    it('should verify Ea in constant time before exposing Eb', function() {
      const connection = newConnection(officialAddressOptions);
      const originalTimingSafeEqual = nodeCrypto.timingSafeEqual;
      let comparisonCount = 0;
      let firstComparedValue;
      let secondComparedValue;

      completeDhKeyMaterial(connection);

      const expectedEa =
        connection.smp._scKeyExchange.expectedPeerDhKeyCheck;
      const expectedEb = Buffer.from(
        connection.smp._scKeyExchange.localDhKeyCheck
      );
      const peerPdu = Smp.buildPairingDhKeyCheckPdu(expectedEa);
      const originalPeerPdu = Buffer.from(peerPdu);

      nodeCrypto.timingSafeEqual = function(first, second) {
        comparisonCount++;
        firstComparedValue = Buffer.from(first);
        secondComparedValue = Buffer.from(second);
        return originalTimingSafeEqual(first, second);
      };

      try {
        connection.smp.processScDhKeyCheckPdu(peerPdu);
      } finally {
        nodeCrypto.timingSafeEqual = originalTimingSafeEqual;
      }

      assert.strictEqual(comparisonCount, 1);
      assert.deepStrictEqual(firstComparedValue, secondComparedValue);
      assertZeroed(expectedEa);
      assert.strictEqual(
        connection.smp._scKeyExchange.expectedPeerDhKeyCheck,
        null
      );
      assert.strictEqual(
        connection.smp._scKeyExchange.confirmRandomStage,
        'peerDhKeyCheckVerified'
      );
      assert.deepStrictEqual(peerPdu, originalPeerPdu);

      const localPdu = connection.smp.buildScDhKeyCheckPdu();
      const originalLocalCheck = Buffer.from(
        connection.smp._scKeyExchange.localDhKeyCheck
      );

      assert.deepStrictEqual(
        Smp.parsePairingDhKeyCheckPdu(localPdu),
        expectedEb
      );
      assert.deepStrictEqual(
        localPdu.slice(1),
        Buffer.from(expectedEb).reverse()
      );
      assert.strictEqual(
        connection.smp._scKeyExchange.confirmRandomStage,
        'dhKeyCheckComplete'
      );

      localPdu.fill(0);

      assert.deepStrictEqual(
        connection.smp._scKeyExchange.localDhKeyCheck,
        originalLocalCheck
      );
    });

    it('should reject a mismatched Ea and clear the context', function() {
      const connection = newConnection(officialAddressOptions);

      completeDhKeyMaterial(connection);

      const context = connection.smp._scKeyExchange;
      const privateKey = context.localPrivateKey;
      const dhKey = context.dhKey;
      const localNonce = context.localNonce;
      const peerNonce = context.peerNonce;
      const localConfirm = context.localConfirm;
      const macKey = context.macKey;
      const ltk = context.ltk;
      const localDhKeyCheck = context.localDhKeyCheck;
      const expectedEa = context.expectedPeerDhKeyCheck;
      const peerPdu = Smp.buildPairingDhKeyCheckPdu(expectedEa);

      peerPdu[1] ^= 0x01;
      const originalPeerPdu = Buffer.from(peerPdu);

      assert.throws(function() {
        connection.smp.processScDhKeyCheckPdu(peerPdu);
      }, /does not match/);

      assert.deepStrictEqual(peerPdu, originalPeerPdu);
      [
        privateKey,
        dhKey,
        localNonce,
        peerNonce,
        localConfirm,
        macKey,
        ltk,
        localDhKeyCheck,
        expectedEa
      ].forEach(assertZeroed);
      assert.strictEqual(connection.smp._scKeyExchange, null);
    });

    it('should reject duplicate and out-of-order DHKey Checks', function() {
      const beforeConfirmComplete =
        newConnection(officialAddressOptions);

      completeKeyExchange(beforeConfirmComplete, privateB, publicA);

      assert.throws(function() {
        beforeConfirmComplete.smp.deriveScKeyMaterial(
          pairingRequest,
          pairingResponse
        );
      }, /Confirm and Random is not complete/);
      assert.strictEqual(beforeConfirmComplete.smp._scKeyExchange, null);

      const localBeforePeer = newConnection(officialAddressOptions);

      completeDhKeyMaterial(localBeforePeer);

      assert.throws(function() {
        localBeforePeer.smp.buildScDhKeyCheckPdu();
      }, /not ready/);
      assert.strictEqual(localBeforePeer.smp._scKeyExchange, null);

      const duplicatePeer = newConnection(officialAddressOptions);

      completeDhKeyMaterial(duplicatePeer);

      const peerPdu = Smp.buildPairingDhKeyCheckPdu(
        duplicatePeer.smp._scKeyExchange.expectedPeerDhKeyCheck
      );

      duplicatePeer.smp.processScDhKeyCheckPdu(peerPdu);

      assert.throws(function() {
        duplicatePeer.smp.processScDhKeyCheckPdu(peerPdu);
      }, /not expected/);
      assert.strictEqual(duplicatePeer.smp._scKeyExchange, null);
    });

    it('should strictly validate pairing and DHKey Check PDUs', function() {
      const invalidPairingType =
        newConnection(officialAddressOptions);

      completeConfirmRandom(invalidPairingType);

      assert.throws(function() {
        invalidPairingType.smp.deriveScKeyMaterial(
          'not a Buffer',
          pairingResponse
        );
      }, TypeError);
      assert.strictEqual(invalidPairingType.smp._scKeyExchange, null);

      const invalidPairingLength =
        newConnection(officialAddressOptions);

      completeConfirmRandom(invalidPairingLength);

      assert.throws(function() {
        invalidPairingLength.smp.deriveScKeyMaterial(
          Buffer.alloc(6),
          pairingResponse
        );
      }, RangeError);
      assert.strictEqual(invalidPairingLength.smp._scKeyExchange, null);

      const invalidPairingOpcode =
        newConnection(officialAddressOptions);

      completeConfirmRandom(invalidPairingOpcode);

      assert.throws(function() {
        invalidPairingOpcode.smp.deriveScKeyMaterial(
          Buffer.from(pairingResponse),
          pairingResponse
        );
      }, RangeError);
      assert.strictEqual(invalidPairingOpcode.smp._scKeyExchange, null);

      const invalidCheck = newConnection(officialAddressOptions);

      completeDhKeyMaterial(invalidCheck);

      assert.throws(function() {
        invalidCheck.smp.processScDhKeyCheckPdu('not a Buffer');
      }, TypeError);
      assert.strictEqual(invalidCheck.smp._scKeyExchange, null);

      const invalidCheckLength =
        newConnection(officialAddressOptions);

      completeDhKeyMaterial(invalidCheckLength);

      assert.throws(function() {
        invalidCheckLength.smp.processScDhKeyCheckPdu(
          Buffer.alloc(16)
        );
      }, RangeError);
      assert.strictEqual(invalidCheckLength.smp._scKeyExchange, null);

      const invalidCheckOpcode =
        newConnection(officialAddressOptions);

      completeDhKeyMaterial(invalidCheckOpcode);

      const invalidPdu = Smp.buildPairingDhKeyCheckPdu(
        invalidCheckOpcode.smp._scKeyExchange
          .expectedPeerDhKeyCheck
      );

      invalidPdu[0] = 0x0c;

      assert.throws(function() {
        invalidCheckOpcode.smp.processScDhKeyCheckPdu(invalidPdu);
      }, RangeError);
      assert.strictEqual(invalidCheckOpcode.smp._scKeyExchange, null);
    });

    it('should clear Phase 3D secrets after success and reset', function() {
      const connection = newConnection(officialAddressOptions);

      completeDhKeyMaterial(connection);

      const expectedEa =
        connection.smp._scKeyExchange.expectedPeerDhKeyCheck;
      const peerPdu = Smp.buildPairingDhKeyCheckPdu(expectedEa);

      connection.smp.processScDhKeyCheckPdu(peerPdu);

      const context = connection.smp._scKeyExchange;
      const privateKey = context.localPrivateKey;
      const dhKey = context.dhKey;
      const localNonce = context.localNonce;
      const peerNonce = context.peerNonce;
      const localConfirm = context.localConfirm;
      const macKey = context.macKey;
      const ltk = context.ltk;
      const localDhKeyCheck = context.localDhKeyCheck;

      connection.smp.buildScDhKeyCheckPdu();
      connection.smp.resetScKeyExchange();

      [
        privateKey,
        dhKey,
        localNonce,
        peerNonce,
        localConfirm,
        macKey,
        ltk,
        localDhKeyCheck,
        expectedEa
      ].forEach(assertZeroed);
      assert.strictEqual(connection.smp._scKeyExchange, null);

      connection.smp.resetScKeyExchange();

      assert.strictEqual(connection.smp._scKeyExchange, null);
    });

    it('should clear Phase 3D secrets when the ACL stream ends', function() {
      const connection = newConnection(officialAddressOptions);

      completeDhKeyMaterial(connection);

      const context = connection.smp._scKeyExchange;
      const macKey = context.macKey;
      const ltk = context.ltk;
      const localDhKeyCheck = context.localDhKeyCheck;
      const expectedEa = context.expectedPeerDhKeyCheck;

      connection.aclStream.emit('end');

      [
        macKey,
        ltk,
        localDhKeyCheck,
        expectedEa
      ].forEach(assertZeroed);
      assert.strictEqual(connection.smp._scKeyExchange, null);
    });

    it('should keep Phase 3D internal and Legacy Pairing unchanged', function() {
      const internalConnection =
        newConnection(officialAddressOptions);

      completeDhKeyMaterial(internalConnection);

      const peerPdu = Smp.buildPairingDhKeyCheckPdu(
        internalConnection.smp._scKeyExchange.expectedPeerDhKeyCheck
      );

      internalConnection.smp.processScDhKeyCheckPdu(peerPdu);
      internalConnection.smp.buildScDhKeyCheckPdu();

      assert.strictEqual(internalConnection.aclStream.writes.length, 0);

      const legacyConnection = newConnection();
      const legacyRequest = Buffer.from([
        0x01,
        0x03,
        0x00,
        0x01,
        0x10,
        0x00,
        0x01
      ]);

      legacyConnection.aclStream.emit('data', 0x0006, legacyRequest);

      assert.strictEqual(legacyConnection.aclStream.writes.length, 1);
      assert.deepStrictEqual(
        legacyConnection.aclStream.writes[0].data,
        Buffer.from([
          0x02,
          0x03,
          0x00,
          0x01,
          0x10,
          0x00,
          0x01
        ])
      );
      assert.strictEqual(legacyConnection.smp._scKeyExchange, null);
    });
  });

  describe('LTK handoff foundation', function() {
    it('should negotiate key size and mask the MSO-first LTK', function() {
      const connection = newConnection(officialAddressOptions);
      const request = Buffer.from(pairingRequest);
      const response = Buffer.from(pairingResponse);
      const originalRequest = Buffer.from(request);
      const originalResponse = Buffer.from(response);
      const expectedMaskedLtk = Buffer.from(expectedLtk);

      request[4] = 12;
      response[4] = 9;
      originalRequest[4] = 12;
      originalResponse[4] = 9;
      expectedMaskedLtk.fill(0, 0, 7);

      completeDhKeyMaterial(connection, request, response);

      assert.strictEqual(connection.smp._scKeyExchange.keySize, 9);
      assert.deepStrictEqual(
        connection.smp._scKeyExchange.ltk,
        expectedMaskedLtk
      );
      assert.deepStrictEqual(request, originalRequest);
      assert.deepStrictEqual(response, originalResponse);
    });

    it('should reject invalid negotiated key sizes', function() {
      const invalidRequest =
        newConnection(officialAddressOptions);
      const shortRequest = Buffer.from(pairingRequest);

      shortRequest[4] = 6;
      completeConfirmRandom(invalidRequest);

      assert.throws(function() {
        invalidRequest.smp.deriveScKeyMaterial(
          shortRequest,
          pairingResponse
        );
      }, RangeError);
      assert.strictEqual(invalidRequest.smp._scKeyExchange, null);

      const invalidResponse =
        newConnection(officialAddressOptions);
      const longResponse = Buffer.from(pairingResponse);

      longResponse[4] = 17;
      completeConfirmRandom(invalidResponse);

      assert.throws(function() {
        invalidResponse.smp.deriveScKeyMaterial(
          pairingRequest,
          longResponse
        );
      }, RangeError);
      assert.strictEqual(invalidResponse.smp._scKeyExchange, null);
    });

    it('should allow handoff only after DHKey Check completion', function() {
      const withoutContext = newConnection(officialAddressOptions);

      assert.throws(function() {
        withoutContext.smp.handoffScEncryptionMaterial();
      }, /not ready/);

      const beforeDhKeyCheck =
        newConnection(officialAddressOptions);

      completeDhKeyMaterial(beforeDhKeyCheck);

      assert.throws(function() {
        beforeDhKeyCheck.smp.handoffScEncryptionMaterial();
      }, /not ready/);
      assert.strictEqual(beforeDhKeyCheck.smp._scKeyExchange, null);
      assert.strictEqual(
        beforeDhKeyCheck.aclStream.pendingScEncryptionMaterial,
        null
      );
    });

    it('should hand off an owned LTK copy only once', function() {
      const connection = newConnection(officialAddressOptions);

      completeDhKeyCheck(connection);

      const sourceLtk = connection.smp._scKeyExchange.ltk;
      const originalLtk = Buffer.from(sourceLtk);

      assert.strictEqual(
        connection.smp._scKeyExchange.confirmRandomStage,
        'dhKeyCheckComplete'
      );

      connection.smp.handoffScEncryptionMaterial();

      const pending =
        connection.aclStream.pendingScEncryptionMaterial;

      assertZeroed(sourceLtk);
      assert.strictEqual(connection.smp._scKeyExchange.ltk, null);
      assert.strictEqual(
        connection.smp._scKeyExchange.confirmRandomStage,
        'ltkHandedOff'
      );
      assert.notStrictEqual(pending.ltk, sourceLtk);
      assert.deepStrictEqual(pending, {
        ltk: originalLtk,
        secureConnections: true,
        authenticated: false,
        bonded: false,
        keySize: 16
      });
      assert.strictEqual(connection.aclStream.writes.length, 0);

      const pendingLtk = pending.ltk;

      assert.throws(function() {
        connection.smp.handoffScEncryptionMaterial();
      }, /not ready/);
      assertZeroed(pendingLtk);
      assert.strictEqual(connection.smp._scKeyExchange, null);
      assert.strictEqual(
        connection.aclStream.pendingScEncryptionMaterial,
        null
      );
    });

    it('should clear local secrets when handoff fails', function() {
      const connection = newConnection(officialAddressOptions);

      completeDhKeyCheck(connection);

      const sourceLtk = connection.smp._scKeyExchange.ltk;
      const privateKey =
        connection.smp._scKeyExchange.localPrivateKey;

      connection.aclStream.setPendingScEncryptionMaterial =
        function() {
          throw new Error('pending storage failed');
        };

      assert.throws(function() {
        connection.smp.handoffScEncryptionMaterial();
      }, /pending storage failed/);
      assertZeroed(sourceLtk);
      assertZeroed(privateKey);
      assert.strictEqual(connection.smp._scKeyExchange, null);
    });

    it('should clear pending LTK on reset, failure, and ACL end', function() {
      const resetConnection =
        newConnection(officialAddressOptions);

      completeDhKeyCheck(resetConnection);
      resetConnection.smp.handoffScEncryptionMaterial();

      const resetLtk =
        resetConnection.aclStream.pendingScEncryptionMaterial.ltk;

      resetConnection.smp.resetScKeyExchange();

      assertZeroed(resetLtk);
      assert.strictEqual(
        resetConnection.aclStream.pendingScEncryptionMaterial,
        null
      );

      const failedConnection =
        newConnection(officialAddressOptions);

      completeDhKeyCheck(failedConnection);
      failedConnection.smp.handoffScEncryptionMaterial();

      const failedLtk =
        failedConnection.aclStream.pendingScEncryptionMaterial.ltk;

      failedConnection.smp.handlePairingFailed(
        Buffer.from([0x05, 0x08])
      );

      assertZeroed(failedLtk);
      assert.strictEqual(
        failedConnection.aclStream.pendingScEncryptionMaterial,
        null
      );

      const endedConnection =
        newConnection(officialAddressOptions);

      completeDhKeyCheck(endedConnection);
      endedConnection.smp.handoffScEncryptionMaterial();

      const endedLtk =
        endedConnection.aclStream.pendingScEncryptionMaterial.ltk;

      endedConnection.aclStream.emit('end');

      assertZeroed(endedLtk);
      assert.strictEqual(
        endedConnection.aclStream.pendingScEncryptionMaterial,
        null
      );
    });
  });

  describe('live SC Just Works responder', function() {
    const livePairingRequest = Buffer.from([
      0x01,
      0x02, // IO capability: KeyboardOnly
      0x00, // OOB data not present
      0x09, // Bonding requested and SC supported, no MITM
      0x10,
      0x00,
      0x00
    ]);
    const iphonePairingRequest = Buffer.from([
      0x01,
      0x04, // IO capability: KeyboardDisplay
      0x00, // OOB data not present
      0x2d, // Bonding, MITM, SC, and CT2 requested
      0x10,
      0x0b,
      0x0b
    ]);
    const livePairingResponse = Buffer.from([
      0x02,
      0x03, // IO capability: NoInputNoOutput
      0x00, // OOB data not present
      0x08, // SC, no MITM, no bonding
      0x10,
      0x00,
      0x00
    ]);
    const liveExpectedEa = bluetoothCrypto.f6(
      expectedMacKey,
      peerNonceA,
      localNonceB,
      Buffer.alloc(16),
      hex('090002'),
      initiatorAddress,
      responderAddress
    );
    const liveExpectedEb = bluetoothCrypto.f6(
      expectedMacKey,
      localNonceB,
      peerNonceA,
      Buffer.alloc(16),
      hex('080003'),
      responderAddress,
      initiatorAddress
    );

    function emitSmp(connection, pdu) {
      connection.aclStream.emit(
        'data',
        0x0006,
        Buffer.from(pdu)
      );
    }

    function withDeterministicRuntime(action) {
      const originalGenerateP256KeyPair =
        bluetoothCrypto.generateP256KeyPair;
      const originalR = bluetoothCrypto.r;

      bluetoothCrypto.generateP256KeyPair = function() {
        return originalGenerateP256KeyPair(privateB);
      };
      bluetoothCrypto.r = function() {
        return Buffer.from(localNonceB);
      };

      try {
        action();
      } finally {
        bluetoothCrypto.generateP256KeyPair =
          originalGenerateP256KeyPair;
        bluetoothCrypto.r = originalR;
      }
    }

    function startLiveSc(connection, request) {
      withDeterministicRuntime(function() {
        emitSmp(
          connection,
          request || livePairingRequest
        );
      });
    }

    function completeLivePublicKey(connection) {
      withDeterministicRuntime(function() {
        if (connection.smp._pairingMode === 'none') {
          emitSmp(connection, livePairingRequest);
        }

        emitSmp(
          connection,
          Smp.buildPairingPublicKeyPdu(publicA)
        );
      });
    }

    function completeLiveRandom(connection) {
      completeLivePublicKey(connection);
      emitSmp(
        connection,
        Smp.buildPairingRandomPdu(peerNonceA)
      );
    }

    function completeLiveDhKeyCheck(connection) {
      completeLiveRandom(connection);
      emitSmp(
        connection,
        Smp.buildPairingDhKeyCheckPdu(liveExpectedEa)
      );
    }

    function lastWrite(connection) {
      const writes = connection.aclStream.writes;
      return writes[writes.length - 1].data;
    }

    it('should negotiate SC and send the non-bonding response', function() {
      const connection = newConnection(officialAddressOptions);
      const request = Buffer.from(livePairingRequest);
      const originalRequest = Buffer.from(request);

      startLiveSc(connection, request);

      assert.deepStrictEqual(request, originalRequest);
      assert.deepStrictEqual(
        connection.aclStream.writes,
        [{
          cid: 0x0006,
          data: livePairingResponse
        }]
      );
      assert.strictEqual(
        connection.smp._pairingMode,
        'secureConnections'
      );
      assert.strictEqual(
        connection.smp._pairingStage,
        'pairingFeaturesExchanged'
      );
      assert.notStrictEqual(connection.smp._scKeyExchange, null);
      assert.notStrictEqual(connection.smp._pairingTimer, null);
    });

    it('should accept the real iPhone SC capabilities request', function() {
      const connection = newConnection(officialAddressOptions);
      const request = Buffer.from(iphonePairingRequest);
      const originalRequest = Buffer.from(request);

      startLiveSc(connection, request);

      assert.deepStrictEqual(request, originalRequest);
      assert.deepStrictEqual(
        connection.aclStream.writes,
        [{
          cid: 0x0006,
          data: livePairingResponse
        }]
      );
      assert.strictEqual(
        connection.smp._pairingMode,
        'secureConnections'
      );
      assert.strictEqual(
        connection.smp._pairingStage,
        'pairingFeaturesExchanged'
      );
      assert.notStrictEqual(connection.smp._scKeyExchange, null);

      completeLivePublicKey(connection);

      assert.deepStrictEqual(
        connection.aclStream.writes.map(function(write) {
          return write.data[0];
        }),
        [0x02, 0x0c, 0x03]
      );
      assert.strictEqual(
        connection.smp._pairingStage,
        'localConfirmSent'
      );
    });

    it('should preserve the Legacy feature response', function() {
      const connection = newConnection();
      const legacyRequest = Buffer.from([
        0x01,
        0x03,
        0x00,
        0x01,
        0x10,
        0x00,
        0x01
      ]);

      emitSmp(connection, legacyRequest);

      assert.deepStrictEqual(
        connection.aclStream.writes[0].data,
        Buffer.from([
          0x02,
          0x03,
          0x00,
          0x01,
          0x10,
          0x00,
          0x01
        ])
      );
      assert.strictEqual(connection.smp._pairingMode, 'legacy');
      assert.strictEqual(connection.smp._scKeyExchange, null);
      assert.strictEqual(connection.smp._pairingTimer, null);
    });

    it('should strictly validate Pairing Request features', function() {
      const cases = [
        {
          update: function(request) {
            return request.slice(0, 6);
          },
          reason: 0x0a
        },
        {
          update: function(request) {
            request[4] = 6;
            return request;
          },
          reason: 0x06
        },
        {
          update: function(request) {
            request[4] = 17;
            return request;
          },
          reason: 0x0a
        },
        {
          update: function(request) {
            request[2] = 1;
            return request;
          },
          reason: 0x02
        }
      ];

      cases.forEach(function(testCase) {
        const connection = newConnection();
        const request = testCase.update(
          Buffer.from(livePairingRequest)
        );
        let failureCount = 0;

        connection.smp.on('fail', function() {
          failureCount++;
        });
        emitSmp(connection, request);

        assert.deepStrictEqual(
          lastWrite(connection),
          Buffer.from([0x05, testCase.reason])
        );
        assert.strictEqual(failureCount, 1);
        assert.strictEqual(connection.smp._scKeyExchange, null);
      });
    });

    it('should lock the selected pairing mode', function() {
      const scConnection = newConnection();
      const legacyRequest = Buffer.from([
        0x01, 0x03, 0x00, 0x01, 0x10, 0x00, 0x01
      ]);

      startLiveSc(scConnection);
      emitSmp(scConnection, legacyRequest);

      assert.deepStrictEqual(
        lastWrite(scConnection),
        Buffer.from([0x05, 0x0a])
      );
      assert.strictEqual(scConnection.aclStream.writes.length, 2);

      emitSmp(scConnection, Buffer.alloc(17, 0x03));

      assert.strictEqual(scConnection.aclStream.writes.length, 2);

      const legacyConnection = newConnection();

      emitSmp(legacyConnection, legacyRequest);
      emitSmp(
        legacyConnection,
        Smp.buildPairingPublicKeyPdu(publicA)
      );

      assert.deepStrictEqual(
        lastWrite(legacyConnection),
        Buffer.from([0x05, 0x07])
      );
      assert.strictEqual(
        legacyConnection.smp._scKeyExchange,
        null
      );
    });

    it('should complete the live responder sequence in exact order', function() {
      const connection = newConnection(officialAddressOptions);
      const mgmtCallCount = mgmtCalls.length;
      let pendingAtEbWrite;
      const originalWrite = connection.aclStream.write;

      connection.aclStream.write = function(cid, data) {
        if (data[0] === 0x0d) {
          pendingAtEbWrite = this.pendingScEncryptionMaterial;
        }

        originalWrite.call(this, cid, data);
      };

      completeLiveDhKeyCheck(connection);

      const expectedConfirm = bluetoothCrypto.f4(
        publicB.slice(0, 32),
        publicA.slice(0, 32),
        localNonceB,
        Buffer.from([0x00])
      );
      const writes = connection.aclStream.writes.map(function(write) {
        return write.data;
      });

      assert.deepStrictEqual(writes, [
        livePairingResponse,
        Smp.buildPairingPublicKeyPdu(publicB),
        Smp.buildPairingConfirmPdu(expectedConfirm),
        Smp.buildPairingRandomPdu(localNonceB),
        Smp.buildPairingDhKeyCheckPdu(liveExpectedEb)
      ]);
      assert.strictEqual(pendingAtEbWrite, null);
      assert.strictEqual(connection.aclStream.pendingSetCount, 1);
      assert.deepStrictEqual(
        connection.aclStream.pendingScEncryptionMaterial,
        {
          ltk: expectedLtk,
          secureConnections: true,
          authenticated: false,
          bonded: false,
          keySize: 16
        }
      );
      assert.strictEqual(
        connection.smp._pairingStage,
        'waitingForEncryption'
      );
      assert.strictEqual(mgmtCalls.length, mgmtCallCount);

      const pendingLtk =
        connection.aclStream.pendingScEncryptionMaterial.ltk;

      connection.aclStream.emit('encryptChange', true);

      assertZeroed(pendingLtk);
      assert.strictEqual(
        connection.aclStream.pendingScEncryptionMaterial,
        null
      );
      assert.strictEqual(connection.smp._scKeyExchange, null);
      assert.strictEqual(connection.smp._pairingMode, 'none');
      assert.strictEqual(connection.smp._pairingStage, 'idle');
      assert.strictEqual(connection.smp._pairingTimer, null);
    });

    it('should reject malformed and invalid public keys', function() {
      const malformed = newConnection(officialAddressOptions);

      startLiveSc(malformed);
      emitSmp(malformed, Buffer.alloc(64, 0x0c));

      assert.deepStrictEqual(
        lastWrite(malformed),
        Buffer.from([0x05, 0x0a])
      );

      const offCurve = newConnection(officialAddressOptions);
      const invalidPublicKey = Buffer.alloc(65);

      invalidPublicKey[0] = 0x0c;
      startLiveSc(offCurve);

      const privateKey =
        offCurve.smp._scKeyExchange.localPrivateKey;

      emitSmp(offCurve, invalidPublicKey);

      assert.deepStrictEqual(
        lastWrite(offCurve),
        Buffer.from([0x05, 0x0b])
      );
      assertZeroed(privateKey);
      assert.strictEqual(offCurve.smp._scKeyExchange, null);
      assert.strictEqual(offCurve.smp._pairingMode, 'none');
    });

    it('should reject duplicate and out-of-order SC commands', function() {
      const randomBeforePublic =
        newConnection(officialAddressOptions);

      startLiveSc(randomBeforePublic);
      emitSmp(
        randomBeforePublic,
        Smp.buildPairingRandomPdu(peerNonceA)
      );
      assert.deepStrictEqual(
        lastWrite(randomBeforePublic),
        Buffer.from([0x05, 0x0a])
      );

      const peerConfirm = newConnection(officialAddressOptions);

      startLiveSc(peerConfirm);
      emitSmp(
        peerConfirm,
        Smp.buildPairingConfirmPdu(Buffer.alloc(16))
      );
      assert.deepStrictEqual(
        lastWrite(peerConfirm),
        Buffer.from([0x05, 0x0a])
      );

      const duplicatePublic =
        newConnection(officialAddressOptions);

      completeLivePublicKey(duplicatePublic);
      emitSmp(
        duplicatePublic,
        Smp.buildPairingPublicKeyPdu(publicA)
      );
      assert.deepStrictEqual(
        lastWrite(duplicatePublic),
        Buffer.from([0x05, 0x0a])
      );

      const duplicateRandom =
        newConnection(officialAddressOptions);

      completeLiveRandom(duplicateRandom);
      emitSmp(
        duplicateRandom,
        Smp.buildPairingRandomPdu(peerNonceA)
      );
      assert.deepStrictEqual(
        lastWrite(duplicateRandom),
        Buffer.from([0x05, 0x0a])
      );

      const duplicateDhKeyCheck =
        newConnection(officialAddressOptions);

      completeLiveDhKeyCheck(duplicateDhKeyCheck);

      const pendingLtk =
        duplicateDhKeyCheck.aclStream
          .pendingScEncryptionMaterial.ltk;

      emitSmp(
        duplicateDhKeyCheck,
        Smp.buildPairingDhKeyCheckPdu(liveExpectedEa)
      );

      assert.deepStrictEqual(
        lastWrite(duplicateDhKeyCheck),
        Buffer.from([0x05, 0x0a])
      );
      assert.strictEqual(
        duplicateDhKeyCheck.aclStream.pendingSetCount,
        1
      );
      assertZeroed(pendingLtk);
      assert.strictEqual(
        duplicateDhKeyCheck.aclStream
          .pendingScEncryptionMaterial,
        null
      );
    });

    it('should reject DHKey Check mismatch without Legacy fallback', function() {
      const connection = newConnection(officialAddressOptions);

      completeLiveRandom(connection);

      const context = connection.smp._scKeyExchange;
      const privateKey = context.localPrivateKey;
      const dhKey = context.dhKey;
      const macKey = context.macKey;
      const ltk = context.ltk;
      const invalidEa = Buffer.from(liveExpectedEa);

      invalidEa[0] ^= 0x01;
      emitSmp(
        connection,
        Smp.buildPairingDhKeyCheckPdu(invalidEa)
      );

      assert.deepStrictEqual(
        lastWrite(connection),
        Buffer.from([0x05, 0x0b])
      );
      [privateKey, dhKey, macKey, ltk].forEach(assertZeroed);
      assert.strictEqual(connection.smp._scKeyExchange, null);
      assert.strictEqual(
        connection.aclStream.pendingScEncryptionMaterial,
        null
      );
      assert.strictEqual(
        connection.aclStream.writes.some(function(write) {
          return write.data.equals(
            Buffer.from([
              0x02, 0x03, 0x00, 0x01, 0x10, 0x00, 0x01
            ])
          );
        }),
        false
      );
    });

    it('should handle unsupported and remote failure commands once', function() {
      const unsupported = newConnection(officialAddressOptions);

      startLiveSc(unsupported);
      emitSmp(unsupported, Buffer.from([0x0e, 0x00]));

      assert.deepStrictEqual(
        lastWrite(unsupported),
        Buffer.from([0x05, 0x07])
      );

      const reserved = newConnection(officialAddressOptions);

      startLiveSc(reserved);

      const reservedWriteCount = reserved.aclStream.writes.length;

      emitSmp(reserved, Buffer.from([0x0f]));
      emitSmp(reserved, Buffer.from([0x00]));

      assert.strictEqual(
        reserved.aclStream.writes.length,
        reservedWriteCount
      );
      assert.strictEqual(
        reserved.smp._pairingMode,
        'secureConnections'
      );

      const remoteFailure = newConnection(officialAddressOptions);
      let failureCount = 0;

      remoteFailure.smp.on('fail', function() {
        failureCount++;
      });
      startLiveSc(remoteFailure);

      const privateKey =
        remoteFailure.smp._scKeyExchange.localPrivateKey;
      const writeCount = remoteFailure.aclStream.writes.length;

      emitSmp(remoteFailure, Buffer.from([0x05, 0x04]));
      emitSmp(remoteFailure, Buffer.from([0x05, 0x04]));

      assert.strictEqual(
        remoteFailure.aclStream.writes.length,
        writeCount
      );
      assert.strictEqual(failureCount, 1);
      assertZeroed(privateKey);
      assert.strictEqual(remoteFailure.smp._scKeyExchange, null);
    });

    it('should not hand off LTK before Eb is queued', function() {
      const connection = newConnection(officialAddressOptions);

      completeLiveRandom(connection);
      connection.aclStream.writeFailureIndex = 4;

      emitSmp(
        connection,
        Smp.buildPairingDhKeyCheckPdu(liveExpectedEa)
      );

      assert.strictEqual(connection.aclStream.pendingSetCount, 0);
      assert.strictEqual(
        connection.aclStream.pendingScEncryptionMaterial,
        null
      );
      assert.strictEqual(connection.smp._scKeyExchange, null);
      assert.strictEqual(connection.smp._pairingMode, 'none');
    });

    it('should apply the 30-second timeout without sending a PDU', function() {
      const connection = newConnection(officialAddressOptions);
      let failureCount = 0;

      connection.smp.on('fail', function() {
        failureCount++;
      });
      startLiveSc(connection);

      const privateKey =
        connection.smp._scKeyExchange.localPrivateKey;
      const writeCount = connection.aclStream.writes.length;

      assert.strictEqual(
        connection.smp._pairingTimer._idleTimeout,
        30000
      );

      connection.smp.onPairingTimeout();

      assert.strictEqual(
        connection.aclStream.writes.length,
        writeCount
      );
      assert.strictEqual(failureCount, 1);
      assertZeroed(privateKey);
      assert.strictEqual(connection.smp._scKeyExchange, null);
      assert.strictEqual(connection.smp._pairingTimer, null);
      assert.strictEqual(connection.smp._pairingTimedOut, true);

      emitSmp(connection, livePairingRequest);

      assert.strictEqual(
        connection.aclStream.writes.length,
        writeCount
      );
    });

    it('should restart the timer after each outgoing SC step', function() {
      const connection = newConnection(officialAddressOptions);

      startLiveSc(connection);

      const afterResponse = connection.smp._pairingTimer;

      completeLivePublicKey(connection);

      const afterConfirm = connection.smp._pairingTimer;

      emitSmp(
        connection,
        Smp.buildPairingRandomPdu(peerNonceA)
      );

      const afterRandom = connection.smp._pairingTimer;

      emitSmp(
        connection,
        Smp.buildPairingDhKeyCheckPdu(liveExpectedEa)
      );

      const afterDhKeyCheck = connection.smp._pairingTimer;

      assert.notStrictEqual(afterResponse, afterConfirm);
      assert.notStrictEqual(afterConfirm, afterRandom);
      assert.notStrictEqual(afterRandom, afterDhKeyCheck);
      assert.strictEqual(afterResponse._destroyed, true);
      assert.strictEqual(afterConfirm._destroyed, true);
      assert.strictEqual(afterRandom._destroyed, true);
      assert.strictEqual(afterDhKeyCheck._idleTimeout, 30000);
    });

    it('should clear secrets on ACL end at every live stage', function() {
      const stageBuilders = [
        startLiveSc,
        completeLivePublicKey,
        completeLiveRandom,
        completeLiveDhKeyCheck
      ];

      stageBuilders.forEach(function(buildStage) {
        const connection = newConnection(officialAddressOptions);

        buildStage(connection);

        const context = connection.smp._scKeyExchange;
        const sensitive = [
          context.localPrivateKey,
          context.dhKey,
          context.localNonce,
          context.peerNonce,
          context.localConfirm,
          context.macKey,
          context.ltk,
          context.localDhKeyCheck,
          context.expectedPeerDhKeyCheck
        ].filter(Buffer.isBuffer);

        if (connection.aclStream.pendingScEncryptionMaterial) {
          sensitive.push(
            connection.aclStream.pendingScEncryptionMaterial.ltk
          );
        }

        connection.aclStream.emit('end');

        sensitive.forEach(assertZeroed);
        assert.strictEqual(connection.smp._scKeyExchange, null);
        assert.strictEqual(connection.smp._pairingTimer, null);
        assert.strictEqual(
          connection.aclStream.pendingScEncryptionMaterial,
          null
        );
      });
    });

    it('should keep secrets out of debug output', function() {
      const debugModule = require('debug');
      const previousDebug = debugModule.disable();
      const originalWrite = process.stderr.write;
      let output = '';

      process.stderr.write = function(value) {
        output += value.toString();
        return true;
      };
      debugModule.enable('smp');

      try {
        const connection = newConnection(officialAddressOptions);

        completeLiveDhKeyCheck(connection);
      } finally {
        process.stderr.write = originalWrite;
        debugModule.enable(previousDebug);
      }

      [
        privateB,
        expectedDhKey,
        localNonceB,
        expectedMacKey,
        expectedLtk,
        liveExpectedEa,
        liveExpectedEb
      ].forEach(function(secret) {
        assert.strictEqual(
          output.indexOf(secret.toString('hex')),
          -1
        );
      });
    });

    it('should preserve the complete Legacy pairing sequence', function() {
      const connection = newConnection();
      const legacyRequest = Buffer.from([
        0x01, 0x03, 0x00, 0x01, 0x10, 0x00, 0x01
      ]);
      const legacyResponse = Buffer.from([
        0x02, 0x03, 0x00, 0x01, 0x10, 0x00, 0x01
      ]);
      const peerRandom = hex(
        '00112233445566778899aabbccddeeff'
      );
      const localRandom = hex(
        'ffeeddccbbaa99887766554433221100'
      );
      const tk = Buffer.alloc(16);
      const mgmtCallCount = mgmtCalls.length;

      emitSmp(connection, legacyRequest);

      const peerConfirm = bluetoothCrypto.c1(
        tk,
        peerRandom,
        legacyResponse,
        legacyRequest,
        connection.smp._iat,
        connection.smp._ia,
        connection.smp._rat,
        connection.smp._ra
      );
      const expectedLocalConfirm = bluetoothCrypto.c1(
        tk,
        localRandom,
        legacyResponse,
        legacyRequest,
        connection.smp._iat,
        connection.smp._ia,
        connection.smp._rat,
        connection.smp._ra
      );
      const expectedStk = bluetoothCrypto.s1(
        tk,
        localRandom,
        peerRandom
      );
      const originalR = bluetoothCrypto.r;

      bluetoothCrypto.r = function() {
        return Buffer.from(localRandom);
      };

      try {
        emitSmp(
          connection,
          Buffer.concat([
            Buffer.from([0x03]),
            peerConfirm
          ])
        );
      } finally {
        bluetoothCrypto.r = originalR;
      }

      emitSmp(
        connection,
        Buffer.concat([
          Buffer.from([0x04]),
          peerRandom
        ])
      );

      assert.deepStrictEqual(
        connection.aclStream.writes.map(function(write) {
          return write.data;
        }),
        [
          legacyResponse,
          Buffer.concat([
            Buffer.from([0x03]),
            expectedLocalConfirm
          ]),
          Buffer.concat([
            Buffer.from([0x04]),
            localRandom
          ])
        ]
      );
      assert.strictEqual(mgmtCalls.length, mgmtCallCount + 1);
      assert.strictEqual(connection.smp._scKeyExchange, null);

      connection.aclStream.emit('encryptChange', true);

      assert.deepStrictEqual(
        connection.aclStream.writes.slice(3).map(function(write) {
          return write.data;
        }),
        [
          Buffer.concat([
            Buffer.from([0x06]),
            expectedStk
          ]),
          Buffer.from([
            0x07,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00
          ])
        ]
      );
      assert.strictEqual(connection.smp._pairingMode, 'none');
      assert.strictEqual(connection.smp._pairingTimer, null);
    });
  });
});
