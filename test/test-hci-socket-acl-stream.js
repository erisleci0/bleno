/* jshint mocha: true */

const assert = require('assert');

const aclStreamPath = require.resolve('../lib/hci-socket/acl-stream');
const smpPath = require.resolve('../lib/hci-socket/smp');
const cachedAclStream = require.cache[aclStreamPath];
const cachedSmp = require.cache[smpPath];

delete require.cache[aclStreamPath];
require.cache[smpPath] = {
  id: smpPath,
  filename: smpPath,
  loaded: true,
  exports: function Smp() {}
};

const AclStream = require(aclStreamPath);

if (cachedSmp) {
  require.cache[smpPath] = cachedSmp;
} else {
  delete require.cache[smpPath];
}

if (cachedAclStream) {
  require.cache[aclStreamPath] = cachedAclStream;
} else {
  delete require.cache[aclStreamPath];
}

const INITIAL_SECURITY_STATE = {
  encrypted: false,
  secureConnections: false,
  authenticated: false,
  bonded: false,
  keySize: 0
};

function createAclStream() {
  const hciWrites = [];
  const aclStream = new AclStream(
    {
      queueAclDataPkt: function(handle, cid, data) {
        hciWrites.push({
          handle,
          cid,
          data: Buffer.from(data)
        });
      }
    },
    1,
    'public',
    '00:11:22:33:44:55',
    'public',
    'aa:bb:cc:dd:ee:ff'
  );

  aclStream._testHciWrites = hciWrites;

  return aclStream;
}

function createScEncryptionMaterial(keySize) {
  return {
    ltk: Buffer.from('00112233445566778899aabbccddeeff', 'hex'),
    secureConnections: true,
    authenticated: false,
    bonded: false,
    keySize: keySize === undefined ? 16 : keySize
  };
}

function assertZeroed(value) {
  assert.strictEqual(value.equals(Buffer.alloc(value.length)), true);
}

describe('HCI socket ACL stream security state', function() {
  let aclStream;

  beforeEach(function() {
    aclStream = createAclStream();
  });

  afterEach(function() {
    aclStream.push(null, null);
  });

  it('should initialize the security state', function() {
    assert.deepStrictEqual(aclStream.security, INITIAL_SECURITY_STATE);
    assert.strictEqual(aclStream.encrypted, false);
    assert.strictEqual(Object.isFrozen(aclStream.security), true);
  });

  it('should transition encrypted from false to true', function() {
    aclStream.pushEncrypt(1);

    assert.strictEqual(aclStream.encrypted, true);
    assert.strictEqual(aclStream.security.encrypted, true);
  });

  it('should transition encrypted from true to false', function() {
    aclStream.pushEncrypt(1);
    aclStream.pushEncrypt(0);

    assert.strictEqual(aclStream.encrypted, false);
    assert.strictEqual(aclStream.security.encrypted, false);
  });

  it('should preserve the encryptChange event signature', function() {
    let callCount = 0;

    aclStream.on('encryptChange', function(encrypted) {
      callCount++;
      assert.strictEqual(arguments.length, 1);
      assert.strictEqual(typeof encrypted, 'boolean');
    });

    aclStream.pushEncrypt(1);
    aclStream.pushEncrypt(0);

    assert.strictEqual(callCount, 2);
  });

  it('should update partial state without losing other fields', function() {
    aclStream.updateSecurityState({
      secureConnections: true,
      keySize: 16
    });
    aclStream.updateSecurityState({
      authenticated: true
    });

    assert.deepStrictEqual(aclStream.security, {
      encrypted: false,
      secureConnections: true,
      authenticated: true,
      bonded: false,
      keySize: 16
    });
  });

  it('should emit securityChange with a state snapshot', function() {
    let receivedState;

    aclStream.on('securityChange', function(state) {
      receivedState = state;
    });

    aclStream.updateSecurityState({
      bonded: true,
      keySize: 7
    });

    assert.deepStrictEqual(receivedState, aclStream.security);
    assert.strictEqual(Object.isFrozen(receivedState), true);
  });

  it('should reject invalid update values', function() {
    [
      null,
      'not an object',
      [],
      Buffer.alloc(0)
    ].forEach(function(update) {
      assert.throws(function() {
        aclStream.updateSecurityState(update);
      }, TypeError);
    });

    [
      'encrypted',
      'secureConnections',
      'authenticated',
      'bonded'
    ].forEach(function(field) {
      const update = {};
      update[field] = 1;

      assert.throws(function() {
        aclStream.updateSecurityState(update);
      }, TypeError);
    });

    assert.throws(function() {
      aclStream.updateSecurityState({
        unknown: true
      });
    }, TypeError);
  });

  it('should reject invalid key sizes', function() {
    [
      -1,
      1,
      6,
      7.5,
      17,
      NaN
    ].forEach(function(keySize) {
      assert.throws(function() {
        aclStream.updateSecurityState({
          keySize
        });
      }, RangeError);
    });

    assert.throws(function() {
      aclStream.updateSecurityState({
        keySize: '16'
      });
    }, TypeError);
  });

  it('should accept valid key sizes', function() {
    [7, 16, 0].forEach(function(keySize) {
      aclStream.updateSecurityState({
        keySize
      });

      assert.strictEqual(aclStream.security.keySize, keySize);
    });
  });

  it('should protect the internal state from caller mutation', function() {
    const state = aclStream.security;

    state.encrypted = true;
    state.keySize = 16;
    aclStream.encrypted = true;

    assert.deepStrictEqual(aclStream.security, INITIAL_SECURITY_STATE);
    assert.strictEqual(aclStream.encrypted, false);
  });

  it('should not emit events when state does not change', function() {
    let encryptChangeCount = 0;
    let securityChangeCount = 0;

    aclStream.on('encryptChange', function() {
      encryptChangeCount++;
    });
    aclStream.on('securityChange', function() {
      securityChangeCount++;
    });

    aclStream.pushEncrypt(0);
    aclStream.updateSecurityState({});
    aclStream.updateSecurityState(INITIAL_SECURITY_STATE);

    assert.strictEqual(encryptChangeCount, 0);
    assert.strictEqual(securityChangeCount, 0);
  });

  it('should strictly validate pending SC encryption material', function() {
    [
      null,
      'not an object',
      [],
      Buffer.alloc(0)
    ].forEach(function(material) {
      assert.throws(function() {
        aclStream.setPendingScEncryptionMaterial(material);
      }, TypeError);
    });

    const missingField = createScEncryptionMaterial();
    delete missingField.bonded;

    assert.throws(function() {
      aclStream.setPendingScEncryptionMaterial(missingField);
    }, TypeError);

    const extraField = createScEncryptionMaterial();
    extraField.extra = true;

    assert.throws(function() {
      aclStream.setPendingScEncryptionMaterial(extraField);
    }, TypeError);

    const invalidLtkType = createScEncryptionMaterial();
    invalidLtkType.ltk = 'not a Buffer';

    assert.throws(function() {
      aclStream.setPendingScEncryptionMaterial(invalidLtkType);
    }, TypeError);

    const invalidLtkLength = createScEncryptionMaterial();
    invalidLtkLength.ltk = Buffer.alloc(15);

    assert.throws(function() {
      aclStream.setPendingScEncryptionMaterial(invalidLtkLength);
    }, RangeError);

    [
      'secureConnections',
      'authenticated',
      'bonded'
    ].forEach(function(field) {
      const material = createScEncryptionMaterial();
      material[field] = 1;

      assert.throws(function() {
        aclStream.setPendingScEncryptionMaterial(material);
      }, TypeError);
    });

    [
      {
        secureConnections: false
      },
      {
        authenticated: true
      },
      {
        bonded: true
      }
    ].forEach(function(update) {
      const material = Object.assign(
        createScEncryptionMaterial(),
        update
      );

      assert.throws(function() {
        aclStream.setPendingScEncryptionMaterial(material);
      }, RangeError);
    });

    [6, 7.5, 17].forEach(function(keySize) {
      assert.throws(function() {
        aclStream.setPendingScEncryptionMaterial(
          createScEncryptionMaterial(keySize)
        );
      }, RangeError);
    });

    const invalidKeySizeType = createScEncryptionMaterial();
    invalidKeySizeType.keySize = '16';

    assert.throws(function() {
      aclStream.setPendingScEncryptionMaterial(invalidKeySizeType);
    }, TypeError);
    assert.strictEqual(aclStream._pendingScEncryptionMaterial, null);
  });

  it('should copy and return the pending SC LTK only once', function() {
    const material = createScEncryptionMaterial();
    const originalLtk = Buffer.from(material.ltk);

    assert.strictEqual(
      aclStream.hasPendingScEncryptionMaterial(),
      false
    );

    aclStream.setPendingScEncryptionMaterial(material);

    const storedLtk = aclStream._pendingScEncryptionMaterial.ltk;

    assert.strictEqual(
      aclStream.hasPendingScEncryptionMaterial(),
      true
    );
    assert.notStrictEqual(storedLtk, material.ltk);

    material.ltk.fill(0);

    assert.deepStrictEqual(storedLtk, originalLtk);

    const takenLtk = aclStream.takePendingScLtk();

    assert.notStrictEqual(takenLtk, storedLtk);
    assert.deepStrictEqual(takenLtk, originalLtk);
    assertZeroed(storedLtk);
    assert.strictEqual(
      aclStream._pendingScEncryptionMaterial.ltk,
      null
    );
    assert.strictEqual(
      aclStream._pendingScEncryptionMaterial.keySize,
      16
    );
    assert.strictEqual(
      aclStream.hasPendingScEncryptionMaterial(),
      true
    );
    assert.throws(function() {
      aclStream.takePendingScLtk();
    }, /already been taken/);

    aclStream.pushEncrypt(true);

    assert.deepStrictEqual(aclStream.security, {
      encrypted: true,
      secureConnections: true,
      authenticated: false,
      bonded: false,
      keySize: 16
    });
    assert.strictEqual(aclStream._pendingScEncryptionMaterial, null);
    assert.strictEqual(
      aclStream.hasPendingScEncryptionMaterial(),
      false
    );
  });

  it('should reject duplicate pending SC material', function() {
    const first = createScEncryptionMaterial(7);
    const second = createScEncryptionMaterial(16);

    aclStream.setPendingScEncryptionMaterial(first);

    assert.throws(function() {
      aclStream.setPendingScEncryptionMaterial(second);
    }, /already pending/);
    assert.strictEqual(
      aclStream._pendingScEncryptionMaterial.keySize,
      7
    );
  });

  it('should commit pending SC metadata only after encryption', function() {
    const material = createScEncryptionMaterial(12);
    let encryptChangeCount = 0;
    let securityChangeCount = 0;
    let receivedState;
    const onEncryptChange = function(encrypted) {
      encryptChangeCount++;
      assert.strictEqual(encrypted, true);
    };
    const onSecurityChange = function(state) {
      securityChangeCount++;
      receivedState = state;
    };

    aclStream.setPendingScEncryptionMaterial(material);

    const storedLtk = aclStream._pendingScEncryptionMaterial.ltk;

    aclStream.on('encryptChange', onEncryptChange);
    aclStream.on('securityChange', onSecurityChange);

    assert.deepStrictEqual(aclStream.security, INITIAL_SECURITY_STATE);

    aclStream.pushEncrypt(true);
    aclStream.removeListener('encryptChange', onEncryptChange);
    aclStream.removeListener('securityChange', onSecurityChange);

    assert.deepStrictEqual(aclStream.security, {
      encrypted: true,
      secureConnections: true,
      authenticated: false,
      bonded: false,
      keySize: 12
    });
    assert.strictEqual(encryptChangeCount, 1);
    assert.strictEqual(securityChangeCount, 1);
    assert.strictEqual(
      Object.prototype.hasOwnProperty.call(receivedState, 'ltk'),
      false
    );
    assert.strictEqual(
      Object.prototype.hasOwnProperty.call(aclStream.security, 'ltk'),
      false
    );
    assertZeroed(storedLtk);
    assert.strictEqual(aclStream._pendingScEncryptionMaterial, null);
    assert.strictEqual(aclStream._testHciWrites.length, 0);
  });

  it('should preserve Legacy encryption without pending SC material', function() {
    aclStream.pushEncrypt(true);

    assert.deepStrictEqual(aclStream.security, {
      encrypted: true,
      secureConnections: false,
      authenticated: false,
      bonded: false,
      keySize: 0
    });
  });

  it('should clear pending material and SC state on encryption off', function() {
    aclStream.setPendingScEncryptionMaterial(
      createScEncryptionMaterial(16)
    );

    const storedLtk = aclStream._pendingScEncryptionMaterial.ltk;

    aclStream.updateSecurityState({
      encrypted: true,
      secureConnections: true,
      authenticated: false,
      bonded: false,
      keySize: 16
    });
    aclStream.pushEncrypt(false);

    assertZeroed(storedLtk);
    assert.strictEqual(aclStream._pendingScEncryptionMaterial, null);
    assert.deepStrictEqual(aclStream.security, INITIAL_SECURITY_STATE);
  });

  it('should clear pending material on failure and ACL end', function() {
    let ltkNegReplyCount = 0;

    aclStream.setPendingScEncryptionMaterial(
      createScEncryptionMaterial()
    );

    const failedLtk = aclStream._pendingScEncryptionMaterial.ltk;

    aclStream.on('ltkNegReply', function() {
      ltkNegReplyCount++;
    });
    aclStream.pushLtkNegReply();

    assertZeroed(failedLtk);
    assert.strictEqual(aclStream._pendingScEncryptionMaterial, null);
    assert.strictEqual(ltkNegReplyCount, 1);

    aclStream.setPendingScEncryptionMaterial(
      createScEncryptionMaterial()
    );

    const endedLtk = aclStream._pendingScEncryptionMaterial.ltk;

    aclStream.updateSecurityState({
      encrypted: true,
      secureConnections: true,
      keySize: 16
    });
    aclStream.push(null, null);

    assertZeroed(endedLtk);
    assert.strictEqual(aclStream._pendingScEncryptionMaterial, null);
    assert.deepStrictEqual(aclStream.security, INITIAL_SECURITY_STATE);
  });

  it('should not emit state events for pending-only cleanup', function() {
    let encryptChangeCount = 0;
    let securityChangeCount = 0;

    aclStream.on('encryptChange', function() {
      encryptChangeCount++;
    });
    aclStream.on('securityChange', function() {
      securityChangeCount++;
    });

    aclStream.setPendingScEncryptionMaterial(
      createScEncryptionMaterial()
    );
    aclStream.pushEncrypt(false);
    aclStream.clearPendingScEncryptionMaterial();

    assert.strictEqual(encryptChangeCount, 0);
    assert.strictEqual(securityChangeCount, 0);
    assert.deepStrictEqual(aclStream.security, INITIAL_SECURITY_STATE);
  });
});
