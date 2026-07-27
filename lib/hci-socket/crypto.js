const crypto = require('crypto');

const P256_CURVE = 'prime256v1';
const AES_BLOCK_SIZE = 16;
const AES_CMAC_RB = 0x87;
const F5_SALT = Buffer.from('6c888391aaf5a53860370bdb5a6083be', 'hex');
const F5_KEY_ID = Buffer.from('62746c65', 'hex');
const F5_LENGTH = Buffer.from('0100', 'hex');

function r() {
  return crypto.randomBytes(16);
}

function c1(k, r, pres, preq, iat, ia, rat, ra) {
  const p1 = Buffer.concat([
    iat,
    rat,
    preq,
    pres
  ]);

  const p2 = Buffer.concat([
    ra,
    ia,
    Buffer.from('00000000', 'hex')
  ]);

  let res = xor(r, p1);
  res = e(k, res);
  res = xor(res, p2);
  res = e(k, res);

  return res;
}

function s1(k, r1, r2) {
  return e(k, Buffer.concat([
    r2.slice(0, 8),
    r1.slice(0, 8)
  ]));
}

function e(key, data) {
  key = swap(key);
  data = swap(data);

  const cipher = crypto.createCipheriv('aes-128-ecb', key, '');
  cipher.setAutoPadding(false);

  return swap(Buffer.concat([
    cipher.update(data),
    cipher.final()
  ]));
}

function xor(b1, b2) {
  const result = Buffer.alloc(b1.length);

  for (let i = 0; i < b1.length; i++) {
    result[i] = b1[i] ^ b2[i];
  }

  return result;
}

function swap(input) {
  const output = Buffer.alloc(input.length);

  for (let i = 0; i < output.length; i++) {
    output[i] = input[input.length - i - 1];
  }

  return output;
}

function assertBuffer(value, name) {
  if (!Buffer.isBuffer(value)) {
    throw new TypeError(name + ' must be a Buffer');
  }
}

function assertLength(value, length, name) {
  assertBuffer(value, name);

  if (value.length !== length) {
    throw new RangeError(name + ' must be ' + length + ' bytes');
  }
}

function aes128(key, data) {
  const cipher = crypto.createCipheriv('aes-128-ecb', key, '');
  cipher.setAutoPadding(false);

  return Buffer.concat([
    cipher.update(data),
    cipher.final()
  ]);
}

function leftShift(input) {
  const output = Buffer.alloc(input.length);
  let carry = 0;

  for (let i = input.length - 1; i >= 0; i--) {
    output[i] = (input[i] << 1) | carry;
    carry = (input[i] & 0x80) ? 1 : 0;
  }

  return output;
}

// Phase 1 inputs and outputs below are MSO-first; SMP wire conversion is deferred.
function aesCmac(key, message) {
  assertLength(key, AES_BLOCK_SIZE, 'key');
  assertBuffer(message, 'message');

  const zeroBlock = Buffer.alloc(AES_BLOCK_SIZE);
  let l;
  let k1;
  let k2;
  let state = Buffer.alloc(AES_BLOCK_SIZE);
  let lastBlock = Buffer.alloc(AES_BLOCK_SIZE);
  let mixed;

  try {
    l = aes128(key, zeroBlock);
    k1 = leftShift(l);
    if (l[0] & 0x80) {
      k1[AES_BLOCK_SIZE - 1] ^= AES_CMAC_RB;
    }

    k2 = leftShift(k1);
    if (k1[0] & 0x80) {
      k2[AES_BLOCK_SIZE - 1] ^= AES_CMAC_RB;
    }

    const blockCount = Math.max(1, Math.ceil(message.length / AES_BLOCK_SIZE));
    const lastBlockComplete = message.length > 0 && message.length % AES_BLOCK_SIZE === 0;
    const lastBlockOffset = (blockCount - 1) * AES_BLOCK_SIZE;

    message.copy(lastBlock, 0, lastBlockOffset);

    if (lastBlockComplete) {
      mixed = xor(lastBlock, k1);
    } else {
      lastBlock[message.length - lastBlockOffset] = 0x80;
      mixed = xor(lastBlock, k2);
    }

    lastBlock.fill(0);
    lastBlock = mixed;
    mixed = null;

    for (let i = 0; i < blockCount - 1; i++) {
      mixed = xor(state, message.slice(i * AES_BLOCK_SIZE, (i + 1) * AES_BLOCK_SIZE));
      state.fill(0);
      state = aes128(key, mixed);
      mixed.fill(0);
      mixed = null;
    }

    mixed = xor(state, lastBlock);
    return aes128(key, mixed);
  } finally {
    zeroBlock.fill(0);
    if (l) {
      l.fill(0);
    }
    if (k1) {
      k1.fill(0);
    }
    if (k2) {
      k2.fill(0);
    }
    if (state) {
      state.fill(0);
    }
    if (lastBlock) {
      lastBlock.fill(0);
    }
    if (mixed) {
      mixed.fill(0);
    }
  }
}

function generateP256KeyPair(privateKey) {
  const ecdh = crypto.createECDH(P256_CURVE);
  let privateKeyCopy;
  let generatedPrivateKey;
  let publicKey;

  try {
    if (privateKey === undefined) {
      ecdh.generateKeys();
    } else {
      assertLength(privateKey, 32, 'privateKey');
      privateKeyCopy = Buffer.from(privateKey);
      ecdh.setPrivateKey(privateKeyCopy);
    }

    generatedPrivateKey = ecdh.getPrivateKey();
    publicKey = ecdh.getPublicKey(null, 'uncompressed');

    const resultPrivateKey = Buffer.alloc(32);
    generatedPrivateKey.copy(resultPrivateKey, 32 - generatedPrivateKey.length);

    return {
      privateKey: resultPrivateKey,
      publicKey: Buffer.from(publicKey.slice(1))
    };
  } finally {
    if (privateKeyCopy) {
      privateKeyCopy.fill(0);
    }
    if (generatedPrivateKey) {
      generatedPrivateKey.fill(0);
    }
  }
}

function p256UncompressedPublicKey(publicKey) {
  assertLength(publicKey, 64, 'publicKey');

  return Buffer.concat([
    Buffer.from([0x04]),
    publicKey
  ]);
}

function validateP256PublicKey(publicKey) {
  const uncompressedPublicKey = p256UncompressedPublicKey(publicKey);
  const validationPrivateKey = Buffer.alloc(32);
  const ecdh = crypto.createECDH(P256_CURVE);
  let validationSecret;

  validationPrivateKey[31] = 0x01;

  try {
    ecdh.setPrivateKey(validationPrivateKey);
    validationSecret = ecdh.computeSecret(uncompressedPublicKey);
    return true;
  } catch (error) {
    if (error.code === 'ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY') {
      return false;
    }

    throw error;
  } finally {
    validationPrivateKey.fill(0);
    uncompressedPublicKey.fill(0);
    if (validationSecret) {
      validationSecret.fill(0);
    }
  }
}

function computeP256DhKey(privateKey, publicKey) {
  assertLength(privateKey, 32, 'privateKey');
  assertLength(publicKey, 64, 'publicKey');

  const privateKeyCopy = Buffer.from(privateKey);
  const uncompressedPublicKey = p256UncompressedPublicKey(publicKey);
  const ecdh = crypto.createECDH(P256_CURVE);
  let dhKey;

  try {
    ecdh.setPrivateKey(privateKeyCopy);
    dhKey = ecdh.computeSecret(uncompressedPublicKey);
    return Buffer.from(dhKey);
  } finally {
    privateKeyCopy.fill(0);
    uncompressedPublicKey.fill(0);
    if (dhKey) {
      dhKey.fill(0);
    }
  }
}

function f4(u, v, x, z) {
  assertLength(u, 32, 'u');
  assertLength(v, 32, 'v');
  assertLength(x, 16, 'x');
  assertLength(z, 1, 'z');

  const message = Buffer.concat([u, v, z]);

  try {
    return aesCmac(x, message);
  } finally {
    message.fill(0);
  }
}

function f5(w, n1, n2, a1, a2) {
  assertLength(w, 32, 'w');
  assertLength(n1, 16, 'n1');
  assertLength(n2, 16, 'n2');
  assertLength(a1, 7, 'a1');
  assertLength(a2, 7, 'a2');

  let t;
  let message;
  let macMessage;
  let ltkMessage;
  let macKey;
  let ltk;
  let succeeded = false;

  try {
    t = aesCmac(F5_SALT, w);
    message = Buffer.concat([
      F5_KEY_ID,
      n1,
      n2,
      a1,
      a2,
      F5_LENGTH
    ]);
    macMessage = Buffer.concat([Buffer.from([0x00]), message]);
    ltkMessage = Buffer.concat([Buffer.from([0x01]), message]);
    macKey = aesCmac(t, macMessage);
    ltk = aesCmac(t, ltkMessage);
    succeeded = true;

    return {
      macKey,
      ltk
    };
  } finally {
    if (t) {
      t.fill(0);
    }
    if (message) {
      message.fill(0);
    }
    if (macMessage) {
      macMessage.fill(0);
    }
    if (ltkMessage) {
      ltkMessage.fill(0);
    }
    if (!succeeded && macKey) {
      macKey.fill(0);
    }
    if (!succeeded && ltk) {
      ltk.fill(0);
    }
  }
}

function f6(w, n1, n2, r, ioCap, a1, a2) {
  assertLength(w, 16, 'w');
  assertLength(n1, 16, 'n1');
  assertLength(n2, 16, 'n2');
  assertLength(r, 16, 'r');
  assertLength(ioCap, 3, 'ioCap');
  assertLength(a1, 7, 'a1');
  assertLength(a2, 7, 'a2');

  const message = Buffer.concat([n1, n2, r, ioCap, a1, a2]);

  try {
    return aesCmac(w, message);
  } finally {
    message.fill(0);
  }
}

module.exports = {
  r,
  c1,
  s1,
  e,
  aesCmac,
  generateP256KeyPair,
  validateP256PublicKey,
  computeP256DhKey,
  f4,
  f5,
  f6
};
