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
  return new AclStream(
    {
      queueAclDataPkt: function() {}
    },
    1,
    'public',
    '00:11:22:33:44:55',
    'public',
    'aa:bb:cc:dd:ee:ff'
  );
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
});
