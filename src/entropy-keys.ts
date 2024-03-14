import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

import { addressToBytes, bytesToAddress } from './utils/address-conversion';

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
