/* jshint mocha: true */

const assert = require('assert');
const { EventEmitter } = require('events');

class FakeHci extends EventEmitter {
  constructor() {
    super();
    this.replies = [];
    this.negativeReplies = [];
    this.replyError = null;
    this.negativeReplyError = null;
  }

  leLtkReply(handle, ltk) {
    if (this.replyError) {
      throw this.replyError;
    }

    this.replies.push({
      handle,
      ltk: Buffer.from(ltk),
      source: ltk
    });
  }

  leLtkNegReply(handle) {
    if (this.negativeReplyError) {
      throw this.negativeReplyError;
    }

    this.negativeReplies.push(handle);
  }
}

class FakeGap extends EventEmitter {
}

class FakeGatt extends EventEmitter {
}

class FakeAclStream {
  constructor(ltk) {
    this.pending = !!ltk;
    this.ltk = ltk ? Buffer.from(ltk) : null;
    this.takeCount = 0;
    this.encryptChanges = [];
    this.negativeReplyCount = 0;
    this.lastTakenLtk = null;
  }

  hasPendingScEncryptionMaterial() {
    return this.pending;
  }

  takePendingScLtk() {
    this.takeCount++;

    if (!this.pending || !this.ltk) {
      throw new Error('pending SC LTK has already been taken');
    }

    this.lastTakenLtk = Buffer.from(this.ltk);
    this.ltk.fill(0);
    this.ltk = null;

    return this.lastTakenLtk;
  }

  pushEncrypt(encrypted) {
    this.encryptChanges.push(encrypted);

    if (!encrypted) {
      if (this.ltk) {
        this.ltk.fill(0);
      }

      this.ltk = null;
      this.pending = false;
    }
  }

  pushLtkNegReply() {
    this.negativeReplyCount++;
    this.pushEncrypt(false);
  }
}

const bindingsPath = require.resolve('../lib/hci-socket/bindings');
const hciPath = require.resolve('../lib/hci-socket/hci');
const gapPath = require.resolve('../lib/hci-socket/gap');
const gattPath = require.resolve('../lib/hci-socket/gatt');
const aclStreamPath = require.resolve('../lib/hci-socket/acl-stream');
const paths = [
  bindingsPath,
  hciPath,
  gapPath,
  gattPath,
  aclStreamPath
];
const cachedModules = paths.map(function(path) {
  return require.cache[path];
});

delete require.cache[bindingsPath];
require.cache[hciPath] = {
  id: hciPath,
  filename: hciPath,
  loaded: true,
  exports: FakeHci
};
require.cache[gapPath] = {
  id: gapPath,
  filename: gapPath,
  loaded: true,
  exports: FakeGap
};
require.cache[gattPath] = {
  id: gattPath,
  filename: gattPath,
  loaded: true,
  exports: FakeGatt
};
require.cache[aclStreamPath] = {
  id: aclStreamPath,
  filename: aclStreamPath,
  loaded: true,
  exports: FakeAclStream
};

const bindings = require(bindingsPath);

paths.forEach(function(path, index) {
  if (cachedModules[index]) {
    require.cache[path] = cachedModules[index];
  } else {
    delete require.cache[path];
  }
});

function assertZeroed(value) {
  assert.strictEqual(value.equals(Buffer.alloc(value.length)), true);
}

describe('HCI socket Bindings LE LTK routing', function() {
  const handle = 0x000b;
  const ltk = Buffer.from(
    '000102030405060708090a0b0c0d0e0f',
    'hex'
  );
  let hci;
  let aclStream;

  beforeEach(function() {
    hci = new FakeHci();
    aclStream = new FakeAclStream(ltk);
    bindings._hci = hci;
    bindings._handle = handle;
    bindings._aclStream = aclStream;
  });

  afterEach(function() {
    bindings._handle = null;
    bindings._aclStream = null;
  });

  it('should route a valid pending SC request only once', function() {
    bindings.onLeLtkRequest(handle, Buffer.alloc(8), 0);

    assert.strictEqual(aclStream.takeCount, 1);
    assert.strictEqual(hci.replies.length, 1);
    assert.strictEqual(hci.replies[0].handle, handle);
    assert.deepStrictEqual(hci.replies[0].ltk, ltk);
    assertZeroed(hci.replies[0].source);
    assert.strictEqual(hci.negativeReplies.length, 0);
    assert.strictEqual(aclStream.pending, true);

    bindings.onLeLtkRequest(handle, Buffer.alloc(8), 0);

    assert.strictEqual(aclStream.takeCount, 2);
    assert.deepStrictEqual(hci.negativeReplies, [handle]);
    assert.strictEqual(aclStream.pending, false);
  });

  it('should reject non-zero SC Random and EDIV values', function() {
    const random = Buffer.alloc(8);
    random[7] = 1;

    bindings.onLeLtkRequest(handle, random, 0);

    assert.strictEqual(aclStream.takeCount, 0);
    assert.deepStrictEqual(hci.negativeReplies, [handle]);
    assert.strictEqual(aclStream.pending, false);

    aclStream = new FakeAclStream(ltk);
    bindings._aclStream = aclStream;

    bindings.onLeLtkRequest(handle, Buffer.alloc(8), 1);

    assert.strictEqual(aclStream.takeCount, 0);
    assert.deepStrictEqual(hci.negativeReplies, [handle, handle]);
    assert.strictEqual(aclStream.pending, false);

    aclStream = new FakeAclStream(ltk);
    bindings._aclStream = aclStream;

    bindings.onLeLtkRequest(handle, Buffer.alloc(7), 0);

    assert.strictEqual(aclStream.takeCount, 0);
    assert.deepStrictEqual(
      hci.negativeReplies,
      [handle, handle, handle]
    );
    assert.strictEqual(aclStream.pending, false);
  });

  it('should preserve Legacy flow and unknown handles', function() {
    const originalLtk = Buffer.from(aclStream.ltk);

    bindings.onLeLtkRequest(0x000c, Buffer.alloc(8), 0);

    assert.strictEqual(aclStream.takeCount, 0);
    assert.deepStrictEqual(aclStream.ltk, originalLtk);
    assert.strictEqual(hci.replies.length, 0);
    assert.strictEqual(hci.negativeReplies.length, 0);

    aclStream = new FakeAclStream();
    bindings._aclStream = aclStream;

    bindings.onLeLtkRequest(handle, Buffer.alloc(8), 0);

    assert.strictEqual(aclStream.takeCount, 0);
    assert.strictEqual(hci.replies.length, 0);
    assert.strictEqual(hci.negativeReplies.length, 0);
  });

  it('should clean pending metadata when Reply write fails', function() {
    hci.replyError = new Error('HCI write failed');

    bindings.onLeLtkRequest(handle, Buffer.alloc(8), 0);

    assert.strictEqual(aclStream.takeCount, 1);
    assertZeroed(aclStream.lastTakenLtk);
    assert.deepStrictEqual(aclStream.encryptChanges, [false]);
    assert.strictEqual(aclStream.pending, false);
  });

  it('should fail closed for malformed owned requests', function() {
    bindings.onLeLtkRequestError(handle);

    assert.deepStrictEqual(hci.negativeReplies, [handle]);
    assert.deepStrictEqual(aclStream.encryptChanges, [false]);
    assert.strictEqual(aclStream.pending, false);

    aclStream = new FakeAclStream(ltk);
    bindings._aclStream = aclStream;

    bindings.onLeLtkRequestError(0x000c);

    assert.strictEqual(aclStream.pending, true);
    assert.deepStrictEqual(hci.negativeReplies, [handle]);

    hci.negativeReplyError = new Error('negative write failed');
    bindings.onLeLtkRequestError(handle);

    assert.strictEqual(aclStream.pending, false);
  });

  it('should handle Reply and Negative Reply completion separately', function() {
    bindings.onLeLtkReplyComplete(0x00, handle);

    assert.deepStrictEqual(aclStream.encryptChanges, []);
    assert.strictEqual(aclStream.pending, true);

    bindings.onLeLtkReplyComplete(0x0c, handle);

    assert.deepStrictEqual(aclStream.encryptChanges, [false]);
    assert.strictEqual(aclStream.pending, false);

    aclStream = new FakeAclStream(ltk);
    bindings._aclStream = aclStream;

    bindings.onLeLtkNegReplyComplete(0x00, handle);

    assert.strictEqual(aclStream.negativeReplyCount, 1);
    assert.strictEqual(aclStream.pending, false);
  });

  it('should commit security only on successful Encryption Change', function() {
    bindings.onEncryptChangeComplete(0x00, handle, 1);
    bindings.onEncryptChangeComplete(0x05, handle, 1);
    bindings.onEncryptChangeComplete(0x00, handle, 0);
    bindings.onEncryptChangeComplete(0x00, 0x000c, 1);

    assert.deepStrictEqual(
      aclStream.encryptChanges,
      [true, false, false]
    );
  });
});
