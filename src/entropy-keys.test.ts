import type { ListEntropySourcesResult } from '@metamask/snaps-sdk';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

import {
  getAllPublicEntropyKeys,
  decryptMessage,
  getEncryptionPublicKey,
  getPublicEntropyKey,
  signMessageWithEntropyKey,
} from './entropy-keys';

const MOCK_PRIVATE_KEY =
  '0xec180de430cef919666c2009b91ca3d3b7f6c471136abc9937fa40b89357bbb9';
const MOCK_PUBLIC_KEY =
  '0x02c291ee55d10abcc46de22b775cb0782b06f386ced8b0d0fccb8007a686bbddad';

const MOCK_PRIVATE_KEY_SRP2 =
  '0x1111111130cef919666c2009b91ca3d3b7f6c471136abc9937fa40b811111111';
const MOCK_PUBLIC_KEY_SRP2 =
  '0x0352d5efbc5060eb6e999eac71aedd37621e5d559e74c42b406b2e73e625f9e3f0';

describe('getPublicEntropyKey() tests', () => {
  it('should return a public key from a known private key', async () => {
    mockSnapGetEntropy();

    const address = await getPublicEntropyKey();
    expect(address).toBe(MOCK_PUBLIC_KEY);
  });

  it('should return a public key from a known private key with a source ID', async () => {
    mockSnapGetEntropy();

    const address = await getPublicEntropyKey('mock_id_2');
    expect(address).toBe(MOCK_PUBLIC_KEY_SRP2);
  });
});

describe('signMessageWithEntropyKey() tests', () => {
  it('should sign a message with a known private key', async () => {
    mockSnapGetEntropy();

    const message = 'hello world';
    const signature = await signMessageWithEntropyKey(message);
    const EXPECTED_SIGNATURE =
      '0x9499d23f16a2fd8511064f7622e0b0c8430d03fd65fda06c85510dfa33e86490781f39d54e880acb76a2ac5a241ba9e68a6a5bee88960ff918c82a54f002492b';
    expect(signature).toBe(EXPECTED_SIGNATURE);
    expect(
      secp256k1.verify(
        signature.substring(2),
        sha256(message),
        MOCK_PUBLIC_KEY.substring(2),
      ),
    ).toBe(true);
  });

  it('signs with the private key from a specific source ID', async () => {
    mockSnapGetEntropy();

    const message = 'hello world';
    const signature = await signMessageWithEntropyKey(message, 'mock_id_2');
    const EXPECTED_SIGNATURE =
      '0xc7cd8af7ddd59287eee7e99f111e637d3e16add417edab1efd388e2688db77dd6e36f1189e47600eeab49c750d4247c5300dbdfbf1d1fad2b6a970070e5148c7';
    expect(signature).toBe(EXPECTED_SIGNATURE);
    expect(
      secp256k1.verify(
        signature.substring(2),
        sha256(message),
        MOCK_PUBLIC_KEY_SRP2.substring(2),
      ),
    ).toBe(true);
  });
});

describe('getAllPublicEntropyKeys() tests', () => {
  it('should get entropy source IDs and SRP IDs relationship map', async () => {
    mockSnapGetEntropy();

    const relationshipMap = await getAllPublicEntropyKeys();
    expect(relationshipMap).toStrictEqual([
      ['mock_id_1', MOCK_PUBLIC_KEY],
      ['mock_id_2', MOCK_PUBLIC_KEY_SRP2],
    ]);
  });
});

describe('encryption tests', () => {
  it('gets the expected encryption key', async () => {
    mockSnapGetEntropy();

    const publicEncryptionKey = await getEncryptionPublicKey();
    const EXPECTED_KEY =
      '0x50cbcf3915730e501b7476e92157307f6e9aade2a2798cf3832f73cd4990281b';
    expect(publicEncryptionKey).toBe(EXPECTED_KEY);
  });

  it('decrypts a message intended for this public encryption key', async () => {
    mockSnapGetEntropy();

    const encrypted = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'h63LvxvCOBP3x3Oou2n5JYgCM1p4p+DF',
      ephemPublicKey: 'lmIBlLKUuSBIRjlo+/hL7ngWYpMWQ7biqk7Y6pDsaXY=',
      ciphertext: 'g+TpY8OlU0AS9VPvaTIIqpFnWNKvWw2COSJY',
    };

    const decrypted = await decryptMessage(encrypted);
    expect(decrypted).toBe('hello world');
  });

  it('fails tp decrypt a message intended for someone else', async () => {
    mockSnapGetEntropy();

    const encrypted = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'h63LvxvCOBP3x3Oou2n5JYgCM1p4p+DF',
      ephemPublicKey: 'lmIBlLKUuSBIRjlo+/hL7ngWYpMWQ7biqk7Y6pDsaXY=',
      ciphertext: 'some/ONE/else/SHOULD/read/this/COSJY',
    };

    await expect(decryptMessage(encrypted)).rejects.toThrow(/invalid tag/u);
  });

  it('decrypts a message intended for a specific public encryption key', async () => {
    mockSnapGetEntropy();

    const encrypted = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'h63LvxvCOBP3x3Oou2n5JYgCM1p4p+DF',
      ephemPublicKey: 'lmIBlLKUuSBIRjlo+/hL7ngWYpMWQ7biqk7Y6pDsaXY=',
      ciphertext: 'g+TpY8OlU0AS9VPvaTIIqpFnWNKvWw2COSJY',
    };

    const decrypted = await decryptMessage(encrypted, 'mock_id_1');
    expect(decrypted).toBe('hello world');
  });

  it('fails to decrypt a message with the wrong version', async () => {
    mockSnapGetEntropy();

    const encrypted = {
      version: 'x25519-something-else-entirely',
      nonce: 'dontcare',
      ephemPublicKey: 'dontcare',
      ciphertext: 'dontcare',
    };

    await expect(decryptMessage(encrypted)).rejects.toThrow(
      /Encryption type\/version not supported \(x25519-something-else-entirely\)./u,
    );
  });
});

function mockSnapGetEntropy() {
  const mockEntropySources = [
    { name: 'source1', id: 'mock_id_1', type: 'mnemonic', primary: true },
    { name: 'source2', id: 'mock_id_2', type: 'mnemonic', primary: false },
  ] as ListEntropySourcesResult;

  const mockSnapRequest = jest
    .fn()
    .mockImplementation(async (r: { method: string; params: any }) => {
      if (r.method === 'snap_listEntropySources') {
        return mockEntropySources;
      } else if (r.method === 'snap_getEntropy') {
        switch (r.params.source) {
          case 'mock_id_2':
            return MOCK_PRIVATE_KEY_SRP2;
          case 'mock_id_1':
          default:
            return MOCK_PRIVATE_KEY;
        }
      }

      throw new Error(`TEST ENV - Snap Request was not mocked: ${r.method}`);
    });

  (global as any).snap = {
    request: mockSnapRequest,
  };
}
