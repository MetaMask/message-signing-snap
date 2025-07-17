import { hsalsa, secretbox } from '@noble/ciphers/salsa';
import { u32, u8 } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { x25519 } from '@noble/curves/ed25519';

const PUBLIC_KEY_BYTES = 32;
const SECRET_KEY_BYTES = 32;
const NONCE_BYTES = 24;
const EXPANDED_KEY_BYTES = 32;

// hardcoded value of `new TextEncoder().encode('expand 32-byte k');`
const _sigma = new Uint8Array([
  101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107,
]);
const _0 = new Uint8Array(16);

const computeSharedKey = (pk: Uint8Array, sk: Uint8Array): Uint8Array => {
  const s = x25519.getSharedSecret(sk, pk);
  const k32 = new Uint32Array(EXPANDED_KEY_BYTES / 4);
  hsalsa(u32(_sigma), u32(s), u32(_0), k32);
  return u8(k32);
};

const checkArrayTypes = (publicKey: any, secretKey: any) => {
  if (!(publicKey instanceof Uint8Array)) {
    throw new TypeError('publicKey must be a Uint8Array');
  }
  if (!(secretKey instanceof Uint8Array)) {
    throw new TypeError('secretKey must be a Uint8Array');
  }
};

const checkKeyLengths = (publicKey: Uint8Array, secretKey: Uint8Array) => {
  if (publicKey.length !== PUBLIC_KEY_BYTES) {
    throw new TypeError(`publicKey must be ${PUBLIC_KEY_BYTES} bytes long`);
  }
  if (secretKey.length !== SECRET_KEY_BYTES) {
    throw new TypeError(`secretKey must be ${SECRET_KEY_BYTES} bytes long`);
  }
};

const boxSeal = (
  message: Uint8Array,
  nonce: Uint8Array,
  pk: Uint8Array,
  sk: Uint8Array,
): Uint8Array => {
  checkArrayTypes(pk, sk);
  checkKeyLengths(pk, sk);
  const k = computeSharedKey(pk, sk);
  return secretbox(k, nonce).seal(message);
};

const boxOpen = (
  box: Uint8Array,
  nonce: Uint8Array,
  pk: Uint8Array,
  sk: Uint8Array,
): Uint8Array => {
  checkArrayTypes(pk, sk);
  checkKeyLengths(pk, sk);
  const k = computeSharedKey(pk, sk);
  return secretbox(k, nonce).open(box);
};

/**
 * This is a NaCl-compatible API for the `box` hybrid encryption scheme.
 * It uses X25519 ECDH for computing the shared secret, the salsa core for KDF, and XSalsa20-Poly1305 for encryption.
 * This API should ideally be published from @noble/ciphers, but they only implement NaCl `secretbox`
 * @see https://nacl.cr.yp.to/box.html
 * @see https://github.com/dchest/tweetnacl-js
 */
export const nacl = {
  box: {
    /**
     * Encrypt a message for a recipient's public key.
     */
    seal: boxSeal,
    /**
     * Decrypt a message using a recipient's secret key.
     */
    open: boxOpen,
    nonceLength: NONCE_BYTES,
    /**
     * Generate a new key pair for encryption.
     * @returns An object containing a secretKey and a publicKey Uint8Array.
     */
    keyPair: (): { secretKey: Uint8Array; publicKey: Uint8Array } => {
      const sk = x25519.utils.randomPrivateKey();
      return { secretKey: sk, publicKey: x25519.getPublicKey(sk) };
    },
  },
  randomBytes: (n: number): Uint8Array => randomBytes(n),
};
