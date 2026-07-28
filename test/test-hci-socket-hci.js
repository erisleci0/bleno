/* jshint mocha: true */

const assert = require('assert');
const { EventEmitter } = require('events');
const Module = require('module');

class FakeSocket extends EventEmitter {
  constructor() {
    super();
    this.writes = [];
    this.writeReferences = [];
    this.writeError = null;
  }

  write(data) {
    this.writeReferences.push(data);

    if (this.writeError) {
      throw this.writeError;
    }

    this.writes.push(Buffer.from(data));
  }
}

const hciPath = require.resolve('../lib/hci-socket/hci');
const cachedHci = require.cache[hciPath];
const originalLoad = Module._load;
const debugMessages = [];

delete require.cache[hciPath];
Module._load = function(request, parent, isMain) {
  if (request === '@abandonware/bluetooth-hci-socket') {
    return FakeSocket;
  }

  if (request === 'debug') {
    return function() {
      return function(message) {
        debugMessages.push(message);
      };
    };
  }

  return originalLoad.call(this, request, parent, isMain);
};

const Hci = require(hciPath);

Module._load = originalLoad;

if (cachedHci) {
  require.cache[hciPath] = cachedHci;
} else {
  delete require.cache[hciPath];
}

function assertZeroed(value) {
  assert.strictEqual(value.equals(Buffer.alloc(value.length)), true);
}

function buildLeLtkRequest(handle, random, ediv) {
  const packet = Buffer.alloc(16);

  packet.writeUInt8(0x04, 0);
  packet.writeUInt8(0x3e, 1);
  packet.writeUInt8(0x0d, 2);
  packet.writeUInt8(0x05, 3);
  packet.writeUInt16LE(handle, 4);
  random.copy(packet, 6);
  packet.writeUInt16LE(ediv, 14);

  return packet;
}

function buildCommandComplete(opcode, status, handle) {
  const packet = Buffer.alloc(9);

  packet.writeUInt8(0x04, 0);
  packet.writeUInt8(0x0e, 1);
  packet.writeUInt8(0x06, 2);
  packet.writeUInt8(0x01, 3);
  packet.writeUInt16LE(opcode, 4);
  packet.writeUInt8(status, 6);
  packet.writeUInt16LE(handle, 7);

  return packet;
}

describe('HCI LE LTK foundation', function() {
  let hci;
  let socket;

  beforeEach(function() {
    hci = new Hci();
    socket = hci._socket;
    debugMessages.length = 0;
  });

  it('should parse LE LTK Request without a Status field', function() {
    const random = Buffer.from('0001020304050607', 'hex');
    const packet = buildLeLtkRequest(0x000b, random, 0x1234);
    const originalPacket = Buffer.from(packet);
    let received;

    hci.on('leLtkRequest', function(handle, receivedRandom, ediv) {
      received = {
        handle,
        random: receivedRandom,
        ediv
      };
    });

    hci.onSocketData(packet);

    assert.deepStrictEqual(received, {
      handle: 0x000b,
      random,
      ediv: 0x1234
    });
    assert.notStrictEqual(received.random, packet.slice(6, 14));

    received.random.fill(0xff);

    assert.deepStrictEqual(packet, originalPacket);
  });

  it('should reject invalid and truncated LE LTK Request events', function() {
    const random = Buffer.alloc(8);
    const errors = [];
    let requestCount = 0;

    hci.on('leLtkRequest', function() {
      requestCount++;
    });
    hci.on('leLtkRequestError', function(handle) {
      errors.push(handle);
    });

    const truncated = buildLeLtkRequest(0x000b, random, 0).slice(0, 10);
    const invalidLength = buildLeLtkRequest(0x000b, random, 0);
    const invalidHandle = buildLeLtkRequest(0x0f00, random, 0);

    invalidLength[2] = 0x0c;

    assert.doesNotThrow(function() {
      hci.onSocketData(truncated);
      hci.onSocketData(invalidLength);
      hci.onSocketData(invalidHandle);
    });
    assert.deepStrictEqual(errors, [0x000b, 0x000b, 0x0f00]);
    assert.strictEqual(requestCount, 0);
  });

  it('should write LE LTK Reply in HCI byte order', function() {
    const ltk = Buffer.from(
      '000102030405060708090a0b0c0d0e0f',
      'hex'
    );
    const originalLtk = Buffer.from(ltk);

    hci.leLtkReply(0x000b, ltk);

    assert.deepStrictEqual(
      socket.writes[0],
      Buffer.from(
        '011a20120b000f0e0d0c0b0a09080706050403020100',
        'hex'
      )
    );
    assert.deepStrictEqual(ltk, originalLtk);
    assertZeroed(socket.writeReferences[0]);
  });

  it('should write LE LTK Negative Reply packet bytes', function() {
    hci.leLtkNegReply(0x000b);

    assert.deepStrictEqual(
      socket.writes[0],
      Buffer.from('011b20020b00', 'hex')
    );
    assertZeroed(socket.writeReferences[0]);
  });

  it('should validate command inputs and clear failed writes', function() {
    const ltk = Buffer.alloc(16, 0xaa);

    assert.throws(function() {
      hci.leLtkReply(0x0f00, ltk);
    }, RangeError);
    assert.throws(function() {
      hci.leLtkReply(0x000b, 'not a Buffer');
    }, TypeError);
    assert.throws(function() {
      hci.leLtkReply(0x000b, Buffer.alloc(15));
    }, RangeError);
    assert.throws(function() {
      hci.leLtkNegReply(-1);
    }, RangeError);

    socket.writeError = new Error('write failed');

    assert.throws(function() {
      hci.leLtkReply(0x000b, ltk);
    }, /write failed/);
    assert.strictEqual(hci._pendingLeLtkReplyHandle, null);
    assertZeroed(socket.writeReferences[0]);
    assert.deepStrictEqual(ltk, Buffer.alloc(16, 0xaa));
  });

  it('should distinguish LTK Reply and Negative Reply completion', function() {
    const ltk = Buffer.alloc(16, 0xaa);
    const replyCompletions = [];
    const negativeCompletions = [];
    const legacyNegativeCompletions = [];

    hci.on('leLtkReplyComplete', function(status, handle) {
      replyCompletions.push([status, handle]);
    });
    hci.on('leLtkNegReplyComplete', function(status, handle) {
      negativeCompletions.push([status, handle]);
    });
    hci.on('leLtkNegReply', function(handle) {
      legacyNegativeCompletions.push(handle);
    });

    hci.leLtkReply(0x000b, ltk);
    hci.onSocketData(buildCommandComplete(0x201a, 0x00, 0x000b));

    hci.leLtkReply(0x000b, ltk);
    hci.onSocketData(buildCommandComplete(0x201a, 0x0c, 0x000b));

    hci.leLtkNegReply(0x000b);
    hci.onSocketData(buildCommandComplete(0x201b, 0x00, 0x000b));

    assert.deepStrictEqual(replyCompletions, [
      [0x00, 0x000b],
      [0x0c, 0x000b]
    ]);
    assert.deepStrictEqual(negativeCompletions, [
      [0x00, 0x000b]
    ]);
    assert.deepStrictEqual(legacyNegativeCompletions, [0x000b]);
  });

  it('should fail closed on malformed LTK command completion', function() {
    const ltk = Buffer.alloc(16, 0xaa);
    const completions = [];

    hci.on('leLtkReplyComplete', function(status, handle) {
      completions.push({
        status,
        handle
      });
    });

    hci.leLtkReply(0x000b, ltk);

    const malformed = buildCommandComplete(
      0x201a,
      0x00,
      0x000b
    ).slice(0, 8);

    hci.onSocketData(malformed);

    hci.leLtkReply(0x000b, ltk);
    hci.onSocketData(buildCommandComplete(0x201a, 0x00, 0x000c));

    hci.leLtkReply(0x000b, ltk);
    hci.onSocketData(
      buildCommandComplete(0x201a, 0x00, 0x000b).slice(0, 6)
    );

    assert.deepStrictEqual(completions, [
      {
        status: 0xff,
        handle: 0x000b
      },
      {
        status: 0xff,
        handle: 0x000b
      },
      {
        status: 0xff,
        handle: 0x000b
      }
    ]);
    assert.strictEqual(hci._pendingLeLtkReplyHandle, null);
  });

  it('should not expose LTK material in logs or completion events', function() {
    const ltk = Buffer.from(
      '000102030405060708090a0b0c0d0e0f',
      'hex'
    );
    const events = [];

    hci.on('leLtkReplyComplete', function(status, handle) {
      events.push([status, handle]);
    });

    hci.leLtkReply(0x000b, ltk);
    hci.onSocketData(buildCommandComplete(0x201a, 0x00, 0x000b));

    const messages = debugMessages.join(' ');

    assert.strictEqual(
      messages.indexOf(ltk.toString('hex')),
      -1
    );
    assert.deepStrictEqual(events, [[0x00, 0x000b]]);
  });

  it('should parse Encryption Change status and preserve its old event', function() {
    const oldEvents = [];
    const completeEvents = [];

    hci.on('encryptChange', function(handle, encrypted) {
      oldEvents.push([handle, encrypted]);
    });
    hci.on('encryptChangeComplete', function(
      status,
      handle,
      encrypted
    ) {
      completeEvents.push([status, handle, encrypted]);
    });

    hci.onSocketData(
      Buffer.from('040804000b0001', 'hex')
    );
    hci.onSocketData(
      Buffer.from('040804050b0001', 'hex')
    );
    hci.onSocketData(
      Buffer.from('040804000b0000', 'hex')
    );
    hci.onSocketData(
      Buffer.from('040803000b00', 'hex')
    );

    assert.deepStrictEqual(oldEvents, [
      [0x000b, 1],
      [0x000b, 1],
      [0x000b, 0]
    ]);
    assert.deepStrictEqual(completeEvents, [
      [0x00, 0x000b, 1],
      [0x05, 0x000b, 1],
      [0x00, 0x000b, 0]
    ]);
  });
});
