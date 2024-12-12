import type { ListEntropySourcesResult } from '@metamask/snaps-sdk';
import type { Eip1024EncryptedData, Hex } from '@metamask/utils';
import { bytesToHex, concatBytes } from '@metamask/utils';
import { utf8ToBytes } from '@noble/ciphers/utils';
import { x25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

import type { EntropySourceId, EntropySourceIdSrpIdMap } from './types';
import { addressToBytes, bytesToAddress } from './utils/address-conversion';
import { ERC1024 } from './utils/ERC1024';

/**
 * Lists the entropy sources available for the snap.
 * @returns Entropy Sources.
 */
async function listEntropySources(): Promise<ListEntropySourcesResult> {
  return await snap.request({
    method: 'snap_listEntropySources',
  });
}

/**
 * Retrieve the snap entropy private key.
 * @param entropySourceId - Optional entropy Source ID following SIP-30.
 * @param salt - The salt used to obtain a domain specific entropy. Metamask internal origins should use `undefined`.
 * @returns Entropy Private Key Hex.
 */
async function getEntropy(
  entropySourceId?: EntropySourceId,
  salt?: string,
): Promise<`0x${string}`> {
  // This is the private key used to derive the public key & message signing
  return await snap.request({
    method: 'snap_getEntropy',
    params: {
      version: 1,
      source: entropySourceId,
      ...(salt ? { salt } : {}),
    },
  });
}

/**
 * Return the entropy private key as an array of bytes.
 * @param entropySourceId - Optional entropy Source ID following SIP-30.
 * @param salt - The salt used to obtain a domain specific entropy. Metamask internal origins should use `undefined`.
 * @returns Private Key Bytes.
 */
async function getPrivateEntropyKey(
  entropySourceId?: EntropySourceId,
  salt?: string,
): Promise<Uint8Array> {
  const privateKeyWith0x = await getEntropy(entropySourceId, salt);
  return addressToBytes(privateKeyWith0x);
}

/**
 * Retrieve the public key for this snap.
 * This public key also serves as an SRP ID.
 * If the entropy source ID is provided, the public key will be derived from that source.
 * Otherwise, the primary entropy source will be used.
 * @param entropySourceId - Optional entropy Source ID following SIP-30.
 * @param salt - The salt used to obtain a domain specific entropy. Metamask internal origins should use `undefined`.
 * @returns Public Key Hex.
 */
export async function getPublicEntropyKey(
  entropySourceId?: EntropySourceId,
  salt?: string,
): Promise<string> {
  const privateKey = await getPrivateEntropyKey(entropySourceId, salt);
  return bytesToAddress(secp256k1.getPublicKey(privateKey));
}

/**
 * Gets an array of all entropy source IDs and their corresponding SRP IDs.
 * @param salt - The salt used to obtain a domain specific entropy. Metamask internal origins should use `undefined`.
 * @returns Entropy Source IDs and SRP IDs Relationship Map.
 */
export async function getAllPublicEntropyKeys(
  salt?: string,
): Promise<EntropySourceIdSrpIdMap> {
  const entropySources = await listEntropySources();
  const entropySourceIdsAndSrpIdsMap: EntropySourceIdSrpIdMap = [];

  await Promise.all(
    entropySources.map(async (entropySource) => {
      const srpId = await getPublicEntropyKey(entropySource.id, salt);
      entropySourceIdsAndSrpIdsMap.push([entropySource.id, srpId]);
    }),
  );

  return entropySourceIdsAndSrpIdsMap;
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
 * @param entropySourceId - Optional entropy Source ID following SIP-30.
 * @param salt - The salt used to obtain a domain specific entropy. Metamask internal origins should use `undefined`.
 * @returns Signed Message String.
 */
export async function signMessageWithEntropyKey(
  message: string,
  entropySourceId?: EntropySourceId,
  salt?: string,
): Promise<string> {
  const privateKey = await getPrivateEntropyKey(entropySourceId, salt);

  // We will create the signature using a sha result from the incoming message
  const shaMessage = sha256(message);
  const signedMessageSignature = secp256k1.sign(shaMessage, privateKey);

  // generate compact signature
  const compactSignature = signedMessageSignature.toCompactHex();
  return `0x${compactSignature}`;
}
