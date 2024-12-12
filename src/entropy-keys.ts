import type { Eip1024EncryptedData, Hex } from '@metamask/utils';
import { bytesToHex, concatBytes } from '@metamask/utils';
import { utf8ToBytes } from '@noble/ciphers/utils';
import { x25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

import { addressToBytes, bytesToAddress } from './utils/address-conversion';
import { ERC1024 } from './utils/ERC1024';

/**
 * Retrieve the snap entropy private key.
 * @returns Entropy Private Key Hex.
 */
async function getEntropy(): Promise<`0x${string}`> {
  const entropy = await snap.request({
    method: 'snap_getEntropy',
    params: {
      version: 1,
    },
  });

  // This is the private key used to derive the public key & message signing
  return entropy;
}

/**
 * Return the entropy private key as an array of bytes.
 * @returns Private Key Bytes.
 */
async function getPrivateEntropyKey(): Promise<Uint8Array> {
  const privateKeyWith0x = await getEntropy();
  return addressToBytes(privateKeyWith0x);
}

/**
 * Retrieve the public key for this snap.
 * @returns Public Key Hex.
 */
export async function getPublicEntropyKey(): Promise<string> {
  const privateKey = await getPrivateEntropyKey();
  return bytesToAddress(secp256k1.getPublicKey(privateKey));
}

// This is used to derive an encryption key from the entropy, to avoid key reuse.
const staticSalt = 'metamask:snaps:encryption';

/**
 * Retrieve the secret encryption key for this snap.
 * The key is derived from the entropy key and a static salt as sha256(entropy | staticSalt).
 * @returns Secret Key Bytes.
 */
async function getEncryptionSecretKey(): Promise<Uint8Array> {
  const privateEntropy = await getPrivateEntropyKey();
  return sha256(concatBytes([privateEntropy, utf8ToBytes(staticSalt)]));
}

/**
 * Retrieve the public encryption key for this snap.
 * @returns Public Key Hex.
 */
export async function getEncryptionPublicKey(): Promise<Hex> {
  const secretKeyBytes = await getEncryptionSecretKey();
  return bytesToHex(x25519.getPublicKey(secretKeyBytes));
}

/**
 * Decrypt an encrypted message using the snap specific encryption key.
 * @param encryptedMessage - The encrypted message, encoded as a `Eip1024EncryptedData` object.
 * @returns The decrypted message (string).
 */
export async function decryptMessage(
  encryptedMessage: Eip1024EncryptedData,
): Promise<string> {
  const secretKeyBytes = await getEncryptionSecretKey();
  return ERC1024.decrypt(encryptedMessage, secretKeyBytes);
}

/**
 * Signs a message and returns the signature.
 * @param message - Message to sign.
 * @returns Signed Message String.
 */
export async function signMessageWithEntropyKey(
  message: string,
): Promise<string> {
  const privateKey = await getPrivateEntropyKey();

  // We will create the signature using a sha result from the incoming message
  const shaMessage = sha256(message);
  const signedMessageSignature = secp256k1.sign(shaMessage, privateKey);

  // generate compact signature
  const compactSignature = signedMessageSignature.toCompactHex();
  return `0x${compactSignature}`;
}
