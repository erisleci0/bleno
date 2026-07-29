/* jshint mocha: true */

const assert = require('assert');
const { EventEmitter } = require('events');

const Characteristic = require('../lib/characteristic');
const Gatt = require('../lib/hci-socket/gatt');
const PrimaryService = require('../lib/primary-service');

const ATT_CID = 0x0004;
const ATT_OP_READ_BY_TYPE_REQ = 0x08;
const ATT_OP_READ_REQ = 0x0a;
const ATT_OP_READ_RESP = 0x0b;
const ATT_OP_WRITE_REQ = 0x12;
const ATT_OP_WRITE_RESP = 0x13;
const ATT_OP_PREP_WRITE_REQ = 0x16;
const ATT_ECODE_INSUFF_ENC = 0x0f;

class FakeAclStream extends EventEmitter {
  constructor() {
    super();
    this.encrypted = false;
    this.writes = [];
  }

  write(cid, data) {
    this.writes.push({
      cid,
      data: Buffer.from(data)
    });
  }
}

function buildHandleRequest(opcode, handle, data) {
  const payload = data || Buffer.alloc(0);
  const request = Buffer.alloc(3 + payload.length);

  request.writeUInt8(opcode, 0);
  request.writeUInt16LE(handle, 1);
  payload.copy(request, 3);

  return request;
}

function buildPrepareWriteRequest(handle, data) {
  const request = Buffer.alloc(5 + data.length);

  request.writeUInt8(ATT_OP_PREP_WRITE_REQ, 0);
  request.writeUInt16LE(handle, 1);
  request.writeUInt16LE(0, 3);
  data.copy(request, 5);

  return request;
}

function buildReadByTypeRequest(startHandle, endHandle, uuid) {
  const request = Buffer.alloc(7);

  request.writeUInt8(ATT_OP_READ_BY_TYPE_REQ, 0);
  request.writeUInt16LE(startHandle, 1);
  request.writeUInt16LE(endHandle, 3);
  request.writeUInt16LE(parseInt(uuid, 16), 5);

  return request;
}

function buildErrorResponse(opcode, handle, status) {
  const response = Buffer.alloc(5);

  response.writeUInt8(0x01, 0);
  response.writeUInt8(opcode, 1);
  response.writeUInt16LE(handle, 2);
  response.writeUInt8(status, 4);

  return response;
}

function findCharacteristicHandle(gatt, characteristic) {
  for (let i = 0; i < gatt._handles.length; i++) {
    const handle = gatt._handles[i];

    if (handle && handle.type === 'characteristic' &&
        handle.attribute === characteristic) {
      return handle;
    }
  }

  throw new Error('characteristic handle not found');
}

describe('HCI socket GATT encryption requirement', function() {
  let aclStream;
  let gatt;
  let secureCharacteristic;
  let unsecuredCharacteristic;
  let secureHandle;
  let unsecuredHandle;
  let secureReadCount;
  let secureWriteCount;
  let unsecuredReadCount;
  let unsecuredWriteCount;

  beforeEach(function() {
    secureReadCount = 0;
    secureWriteCount = 0;
    unsecuredReadCount = 0;
    unsecuredWriteCount = 0;

    secureCharacteristic = new Characteristic({
      uuid: 'fff1',
      properties: ['read', 'write'],
      secure: ['read', 'write'],
      onReadRequest: function(offset, callback) {
        secureReadCount++;
        callback(Characteristic.RESULT_SUCCESS, Buffer.from('secure'));
      },
      onWriteRequest: function(data, offset, withoutResponse, callback) {
        secureWriteCount++;
        callback(Characteristic.RESULT_SUCCESS);
      }
    });

    unsecuredCharacteristic = new Characteristic({
      uuid: 'fff2',
      properties: ['read', 'write'],
      onReadRequest: function(offset, callback) {
        unsecuredReadCount++;
        callback(Characteristic.RESULT_SUCCESS, Buffer.from('open'));
      },
      onWriteRequest: function(data, offset, withoutResponse, callback) {
        unsecuredWriteCount++;
        callback(Characteristic.RESULT_SUCCESS);
      }
    });

    gatt = new Gatt();
    gatt.setServices([
      new PrimaryService({
        uuid: 'fff0',
        characteristics: [
          secureCharacteristic,
          unsecuredCharacteristic
        ]
      })
    ]);

    aclStream = new FakeAclStream();
    gatt.setAclStream(aclStream);

    secureHandle = findCharacteristicHandle(gatt, secureCharacteristic);
    unsecuredHandle = findCharacteristicHandle(gatt, unsecuredCharacteristic);
  });

  afterEach(function() {
    aclStream.emit('end');
  });

  it('should require encryption for a secure read', function() {
    const request = buildHandleRequest(
      ATT_OP_READ_REQ,
      secureHandle.valueHandle
    );

    aclStream.emit('data', ATT_CID, request);

    assert.strictEqual(secureReadCount, 0);
    assert.deepStrictEqual(
      aclStream.writes[0].data,
      buildErrorResponse(
        ATT_OP_READ_REQ,
        secureHandle.valueHandle,
        ATT_ECODE_INSUFF_ENC
      )
    );

    aclStream.encrypted = true;
    aclStream.writes.length = 0;
    aclStream.emit('data', ATT_CID, request);

    assert.strictEqual(secureReadCount, 1);
    assert.deepStrictEqual(
      aclStream.writes[0].data,
      Buffer.concat([
        Buffer.from([ATT_OP_READ_RESP]),
        Buffer.from('secure')
      ])
    );
  });

  it('should require encryption for a secure write', function() {
    const request = buildHandleRequest(
      ATT_OP_WRITE_REQ,
      secureHandle.valueHandle,
      Buffer.from('value')
    );

    aclStream.emit('data', ATT_CID, request);

    assert.strictEqual(secureWriteCount, 0);
    assert.deepStrictEqual(
      aclStream.writes[0].data,
      buildErrorResponse(
        ATT_OP_WRITE_REQ,
        secureHandle.valueHandle,
        ATT_ECODE_INSUFF_ENC
      )
    );

    aclStream.encrypted = true;
    aclStream.writes.length = 0;
    aclStream.emit('data', ATT_CID, request);

    assert.strictEqual(secureWriteCount, 1);
    assert.deepStrictEqual(
      aclStream.writes[0].data,
      Buffer.from([ATT_OP_WRITE_RESP])
    );
  });

  it('should require encryption for secure Read By Type', function() {
    const request = buildReadByTypeRequest(
      secureHandle.startHandle,
      secureHandle.valueHandle,
      secureCharacteristic.uuid
    );

    aclStream.emit('data', ATT_CID, request);

    assert.strictEqual(secureReadCount, 0);
    assert.deepStrictEqual(
      aclStream.writes[0].data,
      buildErrorResponse(
        ATT_OP_READ_BY_TYPE_REQ,
        secureHandle.startHandle,
        ATT_ECODE_INSUFF_ENC
      )
    );
  });

  it('should require encryption for a secure prepared write', function() {
    const request = buildPrepareWriteRequest(
      secureHandle.valueHandle,
      Buffer.from('part')
    );

    aclStream.emit('data', ATT_CID, request);

    assert.strictEqual(secureWriteCount, 0);
    assert.deepStrictEqual(
      aclStream.writes[0].data,
      buildErrorResponse(
        ATT_OP_PREP_WRITE_REQ,
        secureHandle.valueHandle,
        ATT_ECODE_INSUFF_ENC
      )
    );
  });

  it('should preserve unsecured reads and writes without encryption', function() {
    aclStream.emit(
      'data',
      ATT_CID,
      buildHandleRequest(ATT_OP_READ_REQ, unsecuredHandle.valueHandle)
    );
    aclStream.emit(
      'data',
      ATT_CID,
      buildHandleRequest(
        ATT_OP_WRITE_REQ,
        unsecuredHandle.valueHandle,
        Buffer.from('value')
      )
    );

    assert.strictEqual(unsecuredReadCount, 1);
    assert.strictEqual(unsecuredWriteCount, 1);
    assert.deepStrictEqual(
      aclStream.writes[0].data,
      Buffer.concat([
        Buffer.from([ATT_OP_READ_RESP]),
        Buffer.from('open')
      ])
    );
    assert.deepStrictEqual(
      aclStream.writes[1].data,
      Buffer.from([ATT_OP_WRITE_RESP])
    );
  });
});
