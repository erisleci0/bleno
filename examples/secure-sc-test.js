const bleno = require('..');

const Characteristic = bleno.Characteristic;
const PrimaryService = bleno.PrimaryService;

const characteristic = new Characteristic({
  uuid: 'fff1',
  properties: ['read', 'write'],
  secure: ['read', 'write'],

  onReadRequest: function(offset, callback) {
    if (offset !== 0) {
      callback(Characteristic.RESULT_INVALID_OFFSET);
      return;
    }

    callback(
      Characteristic.RESULT_SUCCESS,
      Buffer.from('SC OK')
    );
  },

  onWriteRequest: function(data, offset, withoutResponse, callback) {
    if (offset !== 0) {
      callback(Characteristic.RESULT_INVALID_OFFSET);
      return;
    }

    callback(Characteristic.RESULT_SUCCESS);
  }
});

bleno.on('stateChange', function(state) {
  console.log('Bluetooth state:', state);

  if (state === 'poweredOn') {
    bleno.startAdvertising('Bleno SC Test', ['fff0']);
  } else {
    bleno.stopAdvertising();
  }
});

bleno.on('advertisingStart', function(error) {
  if (error) {
    console.log('Advertising failed');
    return;
  }

  console.log('Advertising started');

  bleno.setServices([
    new PrimaryService({
      uuid: 'fff0',
      characteristics: [characteristic]
    })
  ]);
});

bleno.on('accept', function() {
  const aclStream = bleno._bindings._aclStream;

  if (aclStream) {
    aclStream.on('securityChange', function(state) {
      console.log('Security state:', state);
    });
  }
});
