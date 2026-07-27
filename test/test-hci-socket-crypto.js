/* jshint mocha: true */

const assert = require('assert');

const bluetoothCrypto = require('../lib/hci-socket/crypto');

function hex(value) {
  return Buffer.from(value.replace(/\s/g, ''), 'hex');
}

function reverse(value) {
  return Buffer.from(value).reverse();
}

function assertRejectsNonBuffer(fn, args) {
  args.forEach(function(arg, index) {
    const invalidArgs = args.slice();
    invalidArgs[index] = 'not a Buffer';

    assert.throws(function() {
      fn.apply(null, invalidArgs);
    }, TypeError);
  });
}

function assertRejectsWrongLength(fn, args) {
  args.forEach(function(arg, index) {
    const invalidArgs = args.slice();
    invalidArgs[index] = Buffer.alloc(Math.max(0, arg.length - 1));

    assert.throws(function() {
      fn.apply(null, invalidArgs);
    }, RangeError);
  });
}

describe('HCI socket crypto', function() {
  // RFC 4493, Section 4, Examples 1-4.
  describe('aesCmac', function() {
    const key = hex('2b7e1516 28aed2a6 abf71588 09cf4f3c');
    const vectors = [
      {
        message: hex(''),
        expected: hex('bb1d6929 e9593728 7fa37d12 9b756746')
      },
      {
        message: hex('6bc1bee2 2e409f96 e93d7e11 7393172a'),
        expected: hex('070a16b4 6b4d4144 f79bdd9d d04a287c')
      },
      {
        message: hex(
          '6bc1bee2 2e409f96 e93d7e11 7393172a' +
          'ae2d8a57 1e03ac9c 9eb76fac 45af8e51' +
          '30c81c46 a35ce411'
        ),
        expected: hex('dfa66747 de9ae630 30ca3261 1497c827')
      },
      {
        message: hex(
          '6bc1bee2 2e409f96 e93d7e11 7393172a' +
          'ae2d8a57 1e03ac9c 9eb76fac 45af8e51' +
          '30c81c46 a35ce411 e5fbc119 1a0a52ef' +
          'f69f2445 df4f9b17 ad2b417b e66c3710'
        ),
        expected: hex('51f0bebf 7e3b9d92 fc497417 79363cfe')
      }
    ];

    vectors.forEach(function(vector, index) {
      const descriptions = [
        'empty message',
        'complete block',
        'partial block',
        'multiple complete blocks'
      ];

      it('should match official vector ' + (index + 1) + ' (' +
        descriptions[index] + ')', function() {
        assert.deepStrictEqual(
          bluetoothCrypto.aesCmac(key, vector.message),
          vector.expected
        );
      });
    });

    it('should validate Buffer inputs', function() {
      assertRejectsNonBuffer(bluetoothCrypto.aesCmac, [
        Buffer.alloc(16),
        Buffer.alloc(0)
      ]);
    });

    it('should validate the key length', function() {
      assert.throws(function() {
        bluetoothCrypto.aesCmac(Buffer.alloc(15), Buffer.alloc(0));
      }, RangeError);
    });

    it('should not modify caller buffers', function() {
      const callerKey = Buffer.from(key);
      const callerMessage = Buffer.from(vectors[2].message);
      const originalKey = Buffer.from(callerKey);
      const originalMessage = Buffer.from(callerMessage);

      bluetoothCrypto.aesCmac(callerKey, callerMessage);

      assert.deepStrictEqual(callerKey, originalKey);
      assert.deepStrictEqual(callerMessage, originalMessage);
    });
  });

  // Bluetooth Core Specification Amended 4.2, Vol 2, Part G, Section 7.1.2.
  describe('P-256', function() {
    const dataSets = [
      {
        privateA: hex(
          '3f49f6d4 a3c55f38 74c9b3e3 d2103f50' +
          '4aff607b eb40b799 5899b8a6 cd3c1abd'
        ),
        privateB: hex(
          '55188b3d 32f6bb9a 900afcfb eed4e72a' +
          '59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd'
        ),
        publicA: hex(
          '20b003d2 f297be2c 5e2c83a7 e9f9a5b9' +
          'eff49111 acf4fddb cc030148 0e359de6' +
          'dc809c49 652aeb6d 63329abf 5a52155c' +
          '766345c2 8fed3024 741c8ed0 1589d28b'
        ),
        publicB: hex(
          '1ea1f0f0 1faf1d96 09592284 f19e4c00' +
          '47b58afd 8615a69f 559077b2 2faaa190' +
          '4c55f33e 429dad37 7356703a 9ab85160' +
          '472d1130 e28e3676 5f89aff9 15b1214a'
        ),
        dhKey: hex(
          'ec0234a3 57c8ad05 341010a6 0a397d9b' +
          '99796b13 b4f866f1 868d34f3 73bfa698'
        )
      },
      {
        privateA: hex(
          '06a51669 3c9aa31a 6084545d 0c5db641' +
          'b48572b9 7203ddff b7ac73f7 d0457663'
        ),
        privateB: hex(
          '529aa067 0d72cd64 97502ed4 73502b03' +
          '7e8803b5 c60829a5 a3caa219 505530ba'
        ),
        publicA: hex(
          '2c31a47b 5779809e f44cb5ea af5c3e43' +
          'd5f8faad 4a8794cb 987e9b03 745c78dd' +
          '91951218 3898dfbe cd52e240 8e43871f' +
          'd0211091 17bd3ed4 eaf84377 43715d4f'
        ),
        publicB: hex(
          'f465e43f f23d3f1b 9dc7dfc0 4da87581' +
          '84dbc966 204796ec cf0d6cf5 e16500cc' +
          '0201d048 bcbbd899 eeefc424 164e33c2' +
          '01c2b010 ca6b4d43 a8a155ca d8ecb279'
        ),
        dhKey: hex(
          'ab85843a 2f6d883f 62e5684b 38e30733' +
          '5fe6e194 5ecd1960 4105c6f2 3221eb69'
        )
      }
    ];

    dataSets.forEach(function(dataSet, index) {
      it('should derive public keys for data set ' + (index + 1), function() {
        assert.deepStrictEqual(
          bluetoothCrypto.generateP256KeyPair(dataSet.privateA),
          {
            privateKey: dataSet.privateA,
            publicKey: dataSet.publicA
          }
        );
        assert.deepStrictEqual(
          bluetoothCrypto.generateP256KeyPair(dataSet.privateB),
          {
            privateKey: dataSet.privateB,
            publicKey: dataSet.publicB
          }
        );
        assert.strictEqual(
          bluetoothCrypto.validateP256PublicKey(dataSet.publicA),
          true
        );
        assert.strictEqual(
          bluetoothCrypto.validateP256PublicKey(dataSet.publicB),
          true
        );
      });

      it('should derive the same DHKey from both sides for data set ' + (index + 1), function() {
        const dhKeyA = bluetoothCrypto.computeP256DhKey(
          dataSet.privateA,
          dataSet.publicB
        );
        const dhKeyB = bluetoothCrypto.computeP256DhKey(
          dataSet.privateB,
          dataSet.publicA
        );

        assert.deepStrictEqual(dhKeyA, dataSet.dhKey);
        assert.deepStrictEqual(dhKeyB, dataSet.dhKey);
        assert.deepStrictEqual(dhKeyA, dhKeyB);
      });
    });

    it('should generate a new valid key pair', function() {
      const keyPair = bluetoothCrypto.generateP256KeyPair();

      assert.strictEqual(keyPair.privateKey.length, 32);
      assert.strictEqual(keyPair.publicKey.length, 64);
      assert.strictEqual(
        bluetoothCrypto.validateP256PublicKey(keyPair.publicKey),
        true
      );
    });

    it('should reject invalid private keys', function() {
      assert.throws(function() {
        bluetoothCrypto.generateP256KeyPair('not a Buffer');
      }, TypeError);
      assert.throws(function() {
        bluetoothCrypto.generateP256KeyPair(Buffer.alloc(31));
      }, RangeError);
      assert.throws(function() {
        bluetoothCrypto.generateP256KeyPair(Buffer.alloc(32));
      });
      assert.throws(function() {
        bluetoothCrypto.generateP256KeyPair(Buffer.alloc(32, 0xff));
      });
      assert.throws(function() {
        bluetoothCrypto.computeP256DhKey(
          Buffer.alloc(32),
          dataSets[0].publicA
        );
      });
    });

    it('should reject invalid public-key inputs', function() {
      assert.throws(function() {
        bluetoothCrypto.validateP256PublicKey('not a Buffer');
      }, TypeError);
      assert.throws(function() {
        bluetoothCrypto.validateP256PublicKey(Buffer.alloc(63));
      }, RangeError);
      assert.throws(function() {
        bluetoothCrypto.computeP256DhKey(
          dataSets[0].privateA,
          Buffer.alloc(63)
        );
      }, RangeError);
    });

    it('should reject an off-curve public key', function() {
      const offCurvePublicKey = Buffer.alloc(64);

      assert.strictEqual(
        bluetoothCrypto.validateP256PublicKey(offCurvePublicKey),
        false
      );
      assert.throws(function() {
        bluetoothCrypto.computeP256DhKey(
          dataSets[0].privateA,
          offCurvePublicKey
        );
      });
    });

    it('should validate Buffer inputs for DHKey calculation', function() {
      assertRejectsNonBuffer(bluetoothCrypto.computeP256DhKey, [
        dataSets[0].privateA,
        dataSets[0].publicB
      ]);
    });

    it('should validate DHKey input lengths', function() {
      assertRejectsWrongLength(bluetoothCrypto.computeP256DhKey, [
        dataSets[0].privateA,
        dataSets[0].publicB
      ]);
    });

    it('should not modify caller buffers', function() {
      const privateKey = Buffer.from(dataSets[0].privateA);
      const publicKey = Buffer.from(dataSets[0].publicB);
      const originalPrivateKey = Buffer.from(privateKey);
      const originalPublicKey = Buffer.from(publicKey);

      bluetoothCrypto.generateP256KeyPair(privateKey);
      bluetoothCrypto.validateP256PublicKey(publicKey);
      bluetoothCrypto.computeP256DhKey(privateKey, publicKey);

      assert.deepStrictEqual(privateKey, originalPrivateKey);
      assert.deepStrictEqual(publicKey, originalPublicKey);
    });
  });

  // Bluetooth Core Specification Amended 4.2, Vol 3, Part H, Appendices D.2-D.4.
  describe('LE Secure Connections functions', function() {
    const u = hex(
      '20b003d2 f297be2c 5e2c83a7 e9f9a5b9' +
      'eff49111 acf4fddb cc030148 0e359de6'
    );
    const v = hex(
      '55188b3d 32f6bb9a 900afcfb eed4e72a' +
      '59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd'
    );
    const n1 = hex('d5cb8454 d177733e ffffb2ec 712baeab');
    const n2 = hex('a6e8e7cc 25a75f6e 216583f7 ff3dc4cf');
    const a1 = hex('00561237 37bfce');
    const a2 = hex('00a71370 2dcfc1');
    const dhKey = hex(
      'ec0234a3 57c8ad05 341010a6 0a397d9b' +
      '99796b13 b4f866f1 868d34f3 73bfa698'
    );
    const macKey = hex('2965f176 a1084a02 fd3f6a20 ce636e20');
    const r = hex('12a3343b b453bb54 08da42d2 0c2d0fc8');
    const ioCap = hex('010102');
    const z = Buffer.from([0x00]);

    it('should match the f4 vector', function() {
      assert.deepStrictEqual(
        bluetoothCrypto.f4(u, v, n1, z),
        hex('f2c916f1 07a9bd1c f1eda1be a974872d')
      );
    });

    it('should match the f5 vector', function() {
      assert.deepStrictEqual(
        bluetoothCrypto.f5(dhKey, n1, n2, a1, a2),
        {
          macKey: macKey,
          ltk: hex('69867911 69d7cd23 980522b5 94750a38')
        }
      );
    });

    it('should match the f6 vector', function() {
      assert.deepStrictEqual(
        bluetoothCrypto.f6(macKey, n1, n2, r, ioCap, a1, a2),
        hex('e3c47398 9cd0e8c5 d26c0b09 da958f61')
      );
    });

    it('should validate Buffer inputs', function() {
      assertRejectsNonBuffer(bluetoothCrypto.f4, [
        Buffer.alloc(32),
        Buffer.alloc(32),
        Buffer.alloc(16),
        Buffer.alloc(1)
      ]);
      assertRejectsNonBuffer(bluetoothCrypto.f5, [
        Buffer.alloc(32),
        Buffer.alloc(16),
        Buffer.alloc(16),
        Buffer.alloc(7),
        Buffer.alloc(7)
      ]);
      assertRejectsNonBuffer(bluetoothCrypto.f6, [
        Buffer.alloc(16),
        Buffer.alloc(16),
        Buffer.alloc(16),
        Buffer.alloc(16),
        Buffer.alloc(3),
        Buffer.alloc(7),
        Buffer.alloc(7)
      ]);
    });

    it('should validate all input lengths', function() {
      assertRejectsWrongLength(bluetoothCrypto.f4, [
        Buffer.alloc(32),
        Buffer.alloc(32),
        Buffer.alloc(16),
        Buffer.alloc(1)
      ]);
      assertRejectsWrongLength(bluetoothCrypto.f5, [
        Buffer.alloc(32),
        Buffer.alloc(16),
        Buffer.alloc(16),
        Buffer.alloc(7),
        Buffer.alloc(7)
      ]);
      assertRejectsWrongLength(bluetoothCrypto.f6, [
        Buffer.alloc(16),
        Buffer.alloc(16),
        Buffer.alloc(16),
        Buffer.alloc(16),
        Buffer.alloc(3),
        Buffer.alloc(7),
        Buffer.alloc(7)
      ]);
    });

    it('should not modify caller buffers', function() {
      const inputs = [u, v, n1, n2, a1, a2, dhKey, macKey, r, ioCap, z];
      const originals = inputs.map(function(input) {
        return Buffer.from(input);
      });

      bluetoothCrypto.f4(u, v, n1, z);
      bluetoothCrypto.f5(dhKey, n1, n2, a1, a2);
      bluetoothCrypto.f6(macKey, n1, n2, r, ioCap, a1, a2);

      inputs.forEach(function(input, index) {
        assert.deepStrictEqual(input, originals[index]);
      });
    });
  });

  // Bluetooth Core Specification Amended 4.2, Vol 3, Part H, Sections 2.2.3-2.2.4.
  describe('legacy regression', function() {
    it('should preserve the c1 result', function() {
      const result = bluetoothCrypto.c1(
        reverse(hex('00000000000000000000000000000000')),
        reverse(hex('5783d52156ad6f0e6388274ec6702ee0')),
        reverse(hex('05000800000302')),
        reverse(hex('07071000000101')),
        Buffer.from([0x01]),
        reverse(hex('a1a2a3a4a5a6')),
        Buffer.from([0x00]),
        reverse(hex('b1b2b3b4b5b6'))
      );

      assert.deepStrictEqual(
        reverse(result),
        hex('1e1e3fef878988ead2a74dc5bef13b86')
      );
    });

    it('should preserve the s1 result', function() {
      const result = bluetoothCrypto.s1(
        reverse(hex('00000000000000000000000000000000')),
        reverse(hex('000f0e0d0c0b0a091122334455667788')),
        reverse(hex('010203040506070899aabbccddeeff00'))
      );

      assert.deepStrictEqual(
        reverse(result),
        hex('9a1fe1f0e8b0f49b5b4216ae796da062')
      );
    });
  });
});
