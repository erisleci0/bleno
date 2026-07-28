/* jshint mocha: true */

const assert = require('assert');
const { EventEmitter } = require('events');

const bluetoothCrypto = require('../lib/hci-socket/crypto');

const smpPath = require.resolve('../lib/hci-socket/smp');
const mgmtPath = require.resolve('../lib/hci-socket/mgmt');
const cachedSmp = require.cache[smpPath];
const cachedMgmt = require.cache[mgmtPath];

delete require.cache[smpPath];
require.cache[mgmtPath] = {
  id: mgmtPath,
  filename: mgmtPath,
  loaded: true,
  exports: {
    addLongTermKey: function() {}
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

function createSmp() {
  const aclStream = new EventEmitter();

  aclStream.writes = [];
  aclStream.write = function(cid, data) {
    this.writes.push({
      cid,
      data: Buffer.from(data)
    });
  };

  return {
    aclStream,
    smp: new Smp(
      aclStream,
      'public',
      '00:11:22:33:44:55',
      'public',
      'aa:bb:cc:dd:ee:ff'
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

  it('should reject non-Buffer inputs', function() {
    [
      Smp.msoToSmp,
      Smp.smpToMso,
      Smp.p256PublicKeyMsoToSmp,
      Smp.p256PublicKeySmpToMso,
      Smp.buildPairingPublicKeyPdu,
      Smp.parsePairingPublicKeyPdu,
      Smp.buildPairingDhKeyCheckPdu,
      Smp.parsePairingDhKeyCheckPdu
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
      [Smp.parsePairingDhKeyCheckPdu, 18]
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

    assert.throws(function() {
      Smp.parsePairingPublicKeyPdu(publicKeyPdu);
    }, RangeError);
    assert.throws(function() {
      Smp.parsePairingDhKeyCheckPdu(dhKeyCheckPdu);
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
    const originalPublicKeyPdu = Buffer.from(publicKeyPdu);
    const originalDhKeyCheckPdu = Buffer.from(dhKeyCheckPdu);

    Smp.msoToSmp(inputs[0]);
    Smp.smpToMso(inputs[1]);
    Smp.msoToSmp(inputs[2]);
    Smp.smpToMso(inputs[3]);
    Smp.p256PublicKeyMsoToSmp(inputs[4]);
    Smp.p256PublicKeySmpToMso(inputs[5]);
    Smp.parsePairingPublicKeyPdu(publicKeyPdu);
    Smp.parsePairingDhKeyCheckPdu(dhKeyCheckPdu);

    inputs.forEach(function(input, index) {
      assert.deepStrictEqual(input, originals[index]);
    });
    assert.deepStrictEqual(publicKeyPdu, originalPublicKeyPdu);
    assert.deepStrictEqual(dhKeyCheckPdu, originalDhKeyCheckPdu);
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
  let connections;

  beforeEach(function() {
    connections = [];
  });

  afterEach(function() {
    connections.forEach(function(connection) {
      connection.aclStream.emit('end');
    });
  });

  function newConnection() {
    const connection = createSmp();
    connections.push(connection);
    return connection;
  }

  function completeKeyExchange(connection, localPrivateKey, peerPublicKey) {
    connection.smp.startScKeyExchange(localPrivateKey);
    connection.smp.processScPublicKeyPdu(
      Smp.buildPairingPublicKeyPdu(peerPublicKey)
    );
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

  it('should reset and clear secrets after successful key exchange', function() {
    const connection = newConnection();

    completeKeyExchange(connection, privateB, publicA);

    const privateKey = connection.smp._scKeyExchange.localPrivateKey;
    const dhKey = connection.smp._scKeyExchange.dhKey;

    connection.smp.resetScKeyExchange();

    assertZeroed(privateKey);
    assertZeroed(dhKey);
    assert.strictEqual(connection.smp._scKeyExchange, null);
  });

  it('should reset and clear secrets after pairing failure', function() {
    const connection = newConnection();
    let failCount = 0;

    completeKeyExchange(connection, privateB, publicA);

    const privateKey = connection.smp._scKeyExchange.localPrivateKey;
    const dhKey = connection.smp._scKeyExchange.dhKey;

    connection.smp.on('fail', function() {
      failCount++;
    });
    connection.smp.handlePairingFailed(Buffer.from([0x05, 0x08]));

    assertZeroed(privateKey);
    assertZeroed(dhKey);
    assert.strictEqual(connection.smp._scKeyExchange, null);
    assert.strictEqual(failCount, 1);
  });

  it('should reset and clear secrets when the ACL stream ends', function() {
    const connection = newConnection();

    completeKeyExchange(connection, privateB, publicA);

    const privateKey = connection.smp._scKeyExchange.localPrivateKey;
    const dhKey = connection.smp._scKeyExchange.dhKey;

    connection.aclStream.emit('end');

    assertZeroed(privateKey);
    assertZeroed(dhKey);
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

    assert.strictEqual(connectionA.aclStream.writes.length, 0);
    assert.strictEqual(connectionB.aclStream.writes.length, 0);
  });
});
