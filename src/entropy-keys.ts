import type { ListEntropySourcesResult } from '@metamask/snaps-sdk';
import type { Eip1024EncryptedData } from '@metamask/utils';
import { bytesToHex } from '@metamask/utils';
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
 * @param salt - Optional salt to use for the entropy derivation. Useful for generating keys for different purposes and/or to obtain a domain specific entropy.
 * @returns Entropy Private Key Hex.
 * @see https://metamask.github.io/SIPs/SIPS/sip-6
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
const KEY_PURPOSE_ENCRYPTION = 'metamask:snaps:encryption';

/**
 * Retrieve the secret encryption key for this snap.
 * @param entropySourceId - Optional entropy Source ID following SIP-30.
 * @param extraSalt - The extraSalt used to obtain a domain specific entropy. Metamask internal origins should use `undefined`.
 * @returns Encryption Secret Key Bytes.
 * @see https://metamask.github.io/SIPs/SIPS/sip-6 for more information about how the derivation works.
 */
async function getEncryptionSecretKey(
  entropySourceId?: EntropySourceId,
  extraSalt?: string,
): Promise<`0x${string}`> {
  const salt = extraSalt
    ? `${KEY_PURPOSE_ENCRYPTION}${extraSalt}`
    : KEY_PURPOSE_ENCRYPTION;
  return await getEntropy(entropySourceId, salt);
}

/**
 * Retrieve the public encryption key for this snap.
 * @param entropySourceId - Optional entropy Source ID following SIP-30.
 * @param salt - The salt used to obtain a domain specific entropy. Metamask internal origins should use `undefined`.
 * @returns Public Key Hex.
 */
export async function getEncryptionPublicKey(
  entropySourceId?: EntropySourceId,
  salt?: string,
): Promise<`0x${string}`> {
  const secretKeyHex = await getEncryptionSecretKey(entropySourceId, salt);
  return bytesToHex(x25519.getPublicKey(secretKeyHex.slice(2)));
}

/**
 * Error message for decrypting with the wrong private key.
 * This is thrown by @noble/ciphers, so we will need to match.
 */
const INVALID_TAG_ERROR = 'invalid tag';

/**
 * Decrypt an encrypted message using the snap specific encryption key.
 * In case there are multiple possible private keys, the entropy source ID can be used to specify which one to use.
 * For privacy reasons, it may be impossible to know which entropy source ID to use, so all entropy sources will be tried if this parameter is missing.
 * @param encryptedMessage - The encrypted message, encoded as a `Eip1024EncryptedData` object.
 * @param entropySourceId - Optional entropy Source ID following SIP-30. If this is missing, all available entropy sources will be tried.
 * @param salt - The salt used to obtain a domain specific entropy. Metamask internal origins should use `undefined`.
 * @returns The decrypted message (string).
 */
export async function decryptMessage(
  encryptedMessage: Eip1024EncryptedData,
  entropySourceId?: EntropySourceId,
  salt?: string,
): Promise<string> {
  if (entropySourceId) {
    const secretKeyHex = await getEncryptionSecretKey(entropySourceId, salt);
    return ERC1024.decrypt(encryptedMessage, secretKeyHex);
  }
  const entropySources = await listEntropySources();
  let decryptionError = null;
  for (const source of entropySources) {
    const secretKeyHex = await getEncryptionSecretKey(source.id, salt);
    try {
      return ERC1024.decrypt(encryptedMessage, secretKeyHex);
    } catch (error: any) {
      if (error.message !== INVALID_TAG_ERROR) {
        // If decryption fails because of the key, try the next entropy source.
        // Otherwise, it's likely we matched the correct key so remember the error.
        decryptionError = decryptionError ?? error;
      }
    }
  }
  throw decryptionError ?? new Error(INVALID_TAG_ERROR);
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
