import type { Eip1024EncryptedData, Hex } from '@metamask/utils';
import { base64ToBytes, bytesToBase64, hexToBytes } from '@metamask/utils';
import { bytesToUtf8, utf8ToBytes } from '@noble/ciphers/utils';

import { nacl } from './nacl';

// ported from eth-sig-util
const encrypt = (
  receiverPublicKey: Hex | Uint8Array,
  message: string,
  version: string = 'x25519-xsalsa20-poly1305',
): Eip1024EncryptedData => {
  switch (version) {
    case 'x25519-xsalsa20-poly1305': {
      // generate ephemeral keypair
      const ephemeralKeyPair = nacl.box.keyPair();

      let publicKeyBytes;
      // assemble encryption parameters
      if (receiverPublicKey instanceof Uint8Array) {
        publicKeyBytes = receiverPublicKey;
      } else {
        try {
          publicKeyBytes = hexToBytes(receiverPublicKey);
        } catch (error: any) {
          throw new Error('Bad public key');
        }
      }

      const messageBytes = utf8ToBytes(message);
      const nonce = nacl.randomBytes(nacl.box.nonceLength);

      // encrypt
      const encryptedMessage = nacl.box.seal(
        messageBytes,
        nonce,
        publicKeyBytes,
        ephemeralKeyPair.secretKey,
      );

      // return encrypted data
      return {
        version: 'x25519-xsalsa20-poly1305',
        nonce: bytesToBase64(nonce),
        ephemPublicKey: bytesToBase64(ephemeralKeyPair.publicKey),
        ciphertext: bytesToBase64(encryptedMessage),
      } as Eip1024EncryptedData;
    }
    default:
      throw new Error(`Encryption type/version not supported ${version}`);
  }
};

const decrypt = (
  encryptedData: Eip1024EncryptedData,
  receiverPrivateKey: Hex | Uint8Array,
): string => {
  switch (encryptedData.version) {
    case 'x25519-xsalsa20-poly1305': {
      let secretKey;
      if (receiverPrivateKey instanceof Uint8Array) {
        secretKey = receiverPrivateKey;
      } else {
        try {
          secretKey = hexToBytes(receiverPrivateKey);
        } catch (error: any) {
          throw new Error('Bad private key');
        }
      }

      // assemble decryption parameters
      const nonce = base64ToBytes(encryptedData.nonce);
      const ciphertext = base64ToBytes(encryptedData.ciphertext);
      const ephemPublicKey = base64ToBytes(encryptedData.ephemPublicKey);

      // decrypt or throw 'invalid tag' error
      const decryptedMessage = nacl.box.open(
        ciphertext,
        nonce,
        ephemPublicKey,
        secretKey,
      );

      // return decrypted msg data
      return bytesToUtf8(decryptedMessage);
    }
    default:
      throw new Error(
        `Encryption type/version not supported (${encryptedData.version}).`,
      );
  }
};

/**
 * An encryption and decryption utility matching ERC1024.
 * It uses the `nacl.box` hybrid encryption scheme, along with an Ephemeral sender key to compute the shared secret.
 * This snap only uses the `decrypt` method, but the encryption method is provided for completeness and testing.
 *
 * If we decide to add additional dependencies, this class along with the `nacl` utility could be replaced with `eth-sig-util`.
 * @see https://github.com/ethereum/EIPs/pull/1098
 * @see https://github.com/MetaMask/eth-sig-util/blob/main/src/encryption.ts
 * @see https://nacl.cr.yp.to/box.html
 */
export const ERC1024 = { encrypt, decrypt };
