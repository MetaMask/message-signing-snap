import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

import { addressToBytes, bytesToAddress } from './utils/address-conversion';

// TODO: Remove this import when snap_listEntropySources is implemented
// Temporary work while waiting for snap_listEntropySources to be implemented
export type EntropySource = {
  name: string;
  id: string;
  type: 'mnemonic';
  primary: boolean;
};

/**
 * Lists the entropy sources available for the snap.
 * @returns Entropy Sources.
 */
async function listEntropySources(): Promise<EntropySource[]> {
  const entropySources = await snap.request({
    method: 'snap_listEntropySources',
    params: {
      version: 1,
    },
  } as any);

  return entropySources as EntropySource[];
}

/**
 * Retrieve the snap entropy private key.
 * @param entropySourceId - Optional entropy Source ID following SIP-30.
 * @returns Entropy Private Key Hex.
 */
async function getEntropy(
  entropySourceId?: EntropySource['id'],
): Promise<`0x${string}`> {
  const entropy = await snap.request({
    method: 'snap_getEntropy',
    params: {
      version: 1,
      ...(entropySourceId ? { source: entropySourceId } : {}),
    },
  });

  // This is the private key used to derive the public key & message signing
  return entropy;
}

/**
 * Return the entropy private key as an array of bytes.
 * @param entropySourceId - Optional entropy Source ID following SIP-30.
 * @returns Private Key Bytes.
 */
async function getPrivateEntropyKey(
  entropySourceId?: EntropySource['id'],
): Promise<Uint8Array> {
  const privateKeyWith0x = await getEntropy(entropySourceId);
  return addressToBytes(privateKeyWith0x);
}

/**
 * Retrieve the public key for this snap.
 * This public key also serves as an SRP ID.
 * If the entropy source ID is provided, the public key will be derived from that source.
 * Otherwise, the primary entropy source will be used.
 * @param entropySourceId - Optional entropy Source ID following SIP-30.
 * @returns Public Key Hex.
 */
export async function getPublicEntropyKey(
  entropySourceId?: EntropySource['id'],
): Promise<string> {
  const privateKey = await getPrivateEntropyKey(entropySourceId);
  return bytesToAddress(secp256k1.getPublicKey(privateKey));
}

/**
 * Gets an array of all entropy source IDs and their corresponding SRP IDs.
 * @returns Entropy Source IDs and SRP IDs Relationship Map.
 */
export async function getEntropySourceIdsAndSrpIdsRelationshipMap(): Promise<
  [string, string][]
> {
  const entropySources = await listEntropySources();
  const entropySourceIdsAndSrpIdsMap: [string, string][] = [];

  for (const entropySource of entropySources) {
    const srpId = await getPublicEntropyKey(entropySource.id);
    entropySourceIdsAndSrpIdsMap.push([entropySource.id, srpId]);
  }

  return entropySourceIdsAndSrpIdsMap;
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
