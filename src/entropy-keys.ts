import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

import { addressToBytes, bytesToAddress } from './utils/address-conversion';

/**
 * Retrieve the snap entropy private key.
 */
async function getEntropy() {
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
 */
async function getPrivateEntropyKey() {
  const privateKeyWith0x = await getEntropy();
  return addressToBytes(privateKeyWith0x);
}

/**
 * Retrieve the public key for this snap.
 */
export async function getPublicEntropyKey() {
  const privateKey = await getPrivateEntropyKey();
  return bytesToAddress(secp256k1.getPublicKey(privateKey));
}

/**
 * Signs a message and returns the signature.
 * @param message - Message to sign.
 */
export async function signMessageWithEntropyKey(message: string) {
  const privateKey = await getPrivateEntropyKey();

  // We will create the signature using a sha result from the incoming message
  const shaMessage = sha256(message);
  const signedMessageSignature = secp256k1.sign(shaMessage, privateKey);

  // generate compact signature
  const compactSignature = signedMessageSignature.toCompactHex();
  return `0x${compactSignature}`;
}
