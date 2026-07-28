/* jshint mocha: true */

const assert = require('assert');

const smpPath = require.resolve('../lib/hci-socket/smp');
const mgmtPath = require.resolve('../lib/hci-socket/mgmt');
const cachedSmp = require.cache[smpPath];
const cachedMgmt = require.cache[mgmtPath];

delete require.cache[smpPath];
require.cache[mgmtPath] = {
  id: mgmtPath,
  filename: mgmtPath,
  loaded: true,
  exports: {}
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
