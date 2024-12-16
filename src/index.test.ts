import { installSnap } from '@metamask/snaps-jest';
import type { Hex } from '@metamask/utils';
import { hexToBytes } from '@noble/ciphers/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

import { INTERNAL_ORIGINS } from '.';
import type { EntropySourceIdSrpIdMap } from './types';
import { ERC1024 } from './utils/ERC1024';

describe('onRpcRequest - getPublicKey', () => {
  it('should return this snaps public key', async () => {
    const snap = await installSnap();
    const response = await snap.request({
      method: 'getPublicKey',
      params: {},
    });

    // We cant really test/mock the returned private key, so we can only test the "knowns" features of the public key
    // E.g. length = 68 chars
    // E.g. starts with '0x'
    const result = 'result' in response.response && response.response.result;
    expect(result?.toString()).toMatch(/^0x[0-9a-fA-F]{66}$/u);
  });

  it('should return the same public key for internal domains', async () => {
    const snap = await installSnap();
    const resultsByOrigin = await Promise.all(
      // NOTE!! we can't test for `undefined` origin, as the snapSimulator will default it to `https://metamask.io`
      INTERNAL_ORIGINS.map(async (origin) => {
        return snap.request({
          method: 'getPublicKey',
          params: {},
          origin,
        });
      }),
    );
    const publicKeys = resultsByOrigin.map(
      (result) =>
        'result' in result.response && result.response.result?.toString(),
    );
    expect(publicKeys).toHaveLength(INTERNAL_ORIGINS.length);
    expect(new Set(publicKeys).size).toBe(1);
    expect(typeof publicKeys[0]).toBe('string');
    expect(publicKeys[0]).toMatch(/^0x[0-9a-fA-F]{66}$/u);
  });

  it('should return the different public key for different domains', async () => {
    const snap = await installSnap();
    const differentOrigins = ['origin 1', 'origin 2', ''];
    const resultsByOrigin = await Promise.all(
      differentOrigins.map(async (origin) => {
        return snap.request({
          method: 'getPublicKey',
          params: {},
          origin,
        });
      }),
    );
    const publicKeys = resultsByOrigin.map(
      (result) =>
        'result' in result.response && result.response.result?.toString(),
    );
    expect(publicKeys).toHaveLength(differentOrigins.length);
    expect(new Set(publicKeys).size).toBe(differentOrigins.length);
    publicKeys.forEach((entry) => {
      expect(entry).toBeDefined();
      expect(typeof entry).toBe('string');
      expect(entry).toMatch(/^0x[0-9a-fA-F]{66}$/u);
    });
  });
});

describe('onRpcRequest - getAllPublicKeys', () => {
  it('should return the relationship map of entropy source IDs and SRP IDs', async () => {
    const snap = await installSnap();

    const response = await snap.request({
      method: 'getAllPublicKeys',
    });

    const result =
      'result' in response.response &&
      (response.response.result as unknown as EntropySourceIdSrpIdMap);
    expect(result).toBeDefined();
    expect(typeof result).toBe('object');
    expect((result as EntropySourceIdSrpIdMap).length).toBeGreaterThanOrEqual(
      1,
    );
  });
});

describe('onRpcRequest - getEncryptionPublicKey', () => {
  it('should return this snaps encryption public key', async () => {
    const snap = await installSnap();
    const response = await snap.request({
      method: 'getEncryptionPublicKey',
    });

    // E.g. length = 66 chars
    // E.g. starts with '0x'
    const result = 'result' in response.response && response.response.result;
    expect(result?.toString().length).toBe(66);
    expect(result?.toString().startsWith('0x')).toBe(true);
  });
});

describe('onRpcRequest - decryptMessage', () => {
  it('should decrypt a message intended for the snaps public key', async () => {
    const snap = await installSnap();
    const pkResponse = await snap.request({
      method: 'getEncryptionPublicKey',
    });
    const publicKey = (
      'result' in pkResponse.response && pkResponse.response.result
    )?.toString() as Hex;
    const message = 'hello world';
    const encryptedMessage = ERC1024.encrypt(publicKey, message);
    const response = await snap.request({
      method: 'decryptMessage',
      params: { data: encryptedMessage },
    });

    const result = 'result' in response.response && response.response.result;
    expect(result?.toString()).toBe('hello world');
  });

  it('should fail to decrypt a message intended for a different recipient', async () => {
    const snap = await installSnap();
    const encryptedMessage = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'h63LvxvCOBP3x3Oou2n5JYgCM1p4p+DF',
      ephemPublicKey: 'lmIBlLKUuSBIRjlo+/hL7ngWYpMWQ7biqk7Y6pDsaXY=',
      ciphertext: 'g+TpY8OlU0AS9VPvaTIIqpFnWNKvWw2COSJY',
    };
    const response = await snap.request({
      method: 'decryptMessage',
      params: { data: encryptedMessage },
    });

    expect(response).toRespondWithError({
      code: -32603,
      message: 'invalid tag',
      stack: expect.any(String),
    });
  });

  it('should reject a message with invalid version', async () => {
    const snap = await installSnap();
    const encryptedMessage = {
      version: '1', // invalid version
      nonce: 'h63LvxvCOBP3x3Oou2n5JYgCM1p4p+DF',
      ephemPublicKey: 'lmIBlLKUuSBIRjlo+/hL7ngWYpMWQ7biqk7Y6pDsaXY=',
      ciphertext: 'g+TpY8OlU0AS9VPvaTIIqpFnWNKvWw2COSJY',
    };
    const response = await snap.request({
      method: 'decryptMessage',
      params: { data: encryptedMessage },
    });

    expect(response).toRespondWithError({
      code: -32602,
      message:
        '`decryptMessage`, must take a `data` parameter that must match the Eip1024EncryptedData schema',
      stack: expect.any(String),
    });
  });

  it('should reject a message with missing version', async () => {
    const snap = await installSnap();
    const encryptedMessage = {
      nonce: 'h63LvxvCOBP3x3Oou2n5JYgCM1p4p+DF',
      ephemPublicKey: 'lmIBlLKUuSBIRjlo+/hL7ngWYpMWQ7biqk7Y6pDsaXY=',
      ciphertext: 'g+TpY8OlU0AS9VPvaTIIqpFnWNKvWw2COSJY',
    };
    const response = await snap.request({
      method: 'decryptMessage',
      params: { data: encryptedMessage },
    });

    expect(response).toRespondWithError({
      code: -32602,
      message:
        '`decryptMessage`, must take a `data` parameter that must match the Eip1024EncryptedData schema',
      stack: expect.any(String),
    });
  });

  it('should reject a message with invalid nonce', async () => {
    const snap = await installSnap();
    const encryptedMessage = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'tooshort',
      ephemPublicKey: 'lmIBlLKUuSBIRjlo+/hL7ngWYpMWQ7biqk7Y6pDsaXY=',
      ciphertext: 'g+TpY8OlU0AS9VPvaTIIqpFnWNKvWw2COSJY',
    };
    const response = await snap.request({
      method: 'decryptMessage',
      params: { data: encryptedMessage },
    });

    expect(response).toRespondWithError({
      code: -32602,
      message:
        '`decryptMessage`, must take a `data` parameter that must match the Eip1024EncryptedData schema',
      stack: expect.any(String),
    });
  });

  it('should reject a message with missing nonce', async () => {
    const snap = await installSnap();
    const encryptedMessage = {
      version: 'x25519-xsalsa20-poly1305',
      ephemPublicKey: 'lmIBlLKUuSBIRjlo+/hL7ngWYpMWQ7biqk7Y6pDsaXY=',
      ciphertext: 'g+TpY8OlU0AS9VPvaTIIqpFnWNKvWw2COSJY',
    };
    const response = await snap.request({
      method: 'decryptMessage',
      params: { data: encryptedMessage },
    });

    expect(response).toRespondWithError({
      code: -32602,
      message:
        '`decryptMessage`, must take a `data` parameter that must match the Eip1024EncryptedData schema',
      stack: expect.any(String),
    });
  });

  it('should reject a message with invalid ephemPublicKey', async () => {
    const snap = await installSnap();
    const encryptedMessage = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'h63LvxvCOBP3x3Oou2n5JYgCM1p4p+DF',
      ephemPublicKey: 'invalid base 64',
      ciphertext: 'g+TpY8OlU0AS9VPvaTIIqpFnWNKvWw2COSJY',
    };
    const response = await snap.request({
      method: 'decryptMessage',
      params: { data: encryptedMessage },
    });

    expect(response).toRespondWithError({
      code: -32602,
      message:
        '`decryptMessage`, must take a `data` parameter that must match the Eip1024EncryptedData schema',
      stack: expect.any(String),
    });
  });

  it('should reject a message with missing ephemPublicKey', async () => {
    const snap = await installSnap();
    const encryptedMessage = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'h63LvxvCOBP3x3Oou2n5JYgCM1p4p+DF',
      ciphertext: 'g+TpY8OlU0AS9VPvaTIIqpFnWNKvWw2COSJY',
    };
    const response = await snap.request({
      method: 'decryptMessage',
      params: { data: encryptedMessage },
    });

    expect(response).toRespondWithError({
      code: -32602,
      message:
        '`decryptMessage`, must take a `data` parameter that must match the Eip1024EncryptedData schema',
      stack: expect.any(String),
    });
  });

  it('should reject a message with invalid params type', async () => {
    const snap = await installSnap();
    const encryptedMessage = JSON.stringify({
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'h63LvxvCOBP3x3Oou2n5JYgCM1p4p+DF',
      ephemPublicKey: 'lmIBlLKUuSBIRjlo+/hL7ngWYpMWQ7biqk7Y6pDsaXY=',
      ciphertext: 'g+TpY8OlU0AS9VPvaTIIqpFnWNKvWw2COSJY',
    });
    const response = await snap.request({
      method: 'decryptMessage',
      params: { data: encryptedMessage },
    });

    expect(response).toRespondWithError({
      code: -32602,
      message:
        '`decryptMessage`, must take a `data` parameter that must match the Eip1024EncryptedData schema',
      stack: expect.any(String),
    });
  });
});

describe('onRpcRequest - signMessage', () => {
  it('should return a signature that can be verified for an internal domain', async () => {
    const snap = await installSnap();
    const MESSAGE = 'metamask:hello world';

    // Arrange - get public key
    const publicKeyResponse = await snap.request({
      method: 'getPublicKey',
      origin: '',
    });
    const publicKey = ('result' in publicKeyResponse.response &&
      publicKeyResponse.response.result?.toString()) as string;

    // Act - create signature
    const signatureResponse = await snap.request({
      method: 'signMessage',
      params: { message: MESSAGE },
      origin: 'https://docs.metamask.io', // verifying with another internal domain
    });
    const signature = ('result' in signatureResponse.response &&
      signatureResponse.response.result?.toString()) as string;

    // Assert - validate signature
    expect(signature).toBeDefined();
    expect(verifySignature(signature, MESSAGE, publicKey)).toBe(true);
  });

  it('should return a signature that can be verified, for a specific domain', async () => {
    const snap = await installSnap();
    const MESSAGE = 'metamask:hello world';

    // Arrange - get public key
    const publicKeyResponse = await snap.request({
      method: 'getPublicKey',
      origin: 'https://example.com',
    });
    const publicKey = ('result' in publicKeyResponse.response &&
      publicKeyResponse.response.result?.toString()) as string;

    // Act - create signature
    const signatureResponse = await snap.request({
      method: 'signMessage',
      params: { message: MESSAGE },
      origin: 'https://example.com',
    });
    const signature = ('result' in signatureResponse.response &&
      signatureResponse.response.result?.toString()) as string;

    // Assert - validate signature
    expect(signature).toBeDefined();
    expect(verifySignature(signature, MESSAGE, publicKey)).toBe(true);
  });

  it('fails to verify signature for the wrong origin', async () => {
    const snap = await installSnap();
    const MESSAGE = 'metamask:hello world';

    // Arrange - get public key
    const publicKeyResponse = await snap.request({
      method: 'getPublicKey',
      origin: 'https://example.com',
    });
    const publicKey = ('result' in publicKeyResponse.response &&
      publicKeyResponse.response.result?.toString()) as string;

    // Act - create signature
    const signatureResponse = await snap.request({
      method: 'signMessage',
      params: { message: MESSAGE },
      origin: 'https://counter-example.com',
    });
    const signature = ('result' in signatureResponse.response &&
      signatureResponse.response.result?.toString()) as string;

    // Assert - validate signature
    expect(signature).toBeDefined();
    expect(verifySignature(signature, MESSAGE, publicKey)).toBe(false);
  });

  it('should fail if invalid message provided', async () => {
    const snap = await installSnap();

    function assertInvalidMessage(res: unknown) {
      expect(res).toRespondWithError({
        code: -32602,
        message:
          '`signMessage`, must take a `message` parameter that must begin with `metamask:`',
        stack: expect.any(String),
      });
    }

    // no message
    const responseNoMessage = await snap.request({
      method: 'signMessage',
    });
    assertInvalidMessage(responseNoMessage);

    // message not starting with/tagged with `metamask:`
    const responseUntaggedMessage = await snap.request({
      method: 'signMessage',
      params: { message: 'my custom message' },
    });
    assertInvalidMessage(responseUntaggedMessage);

    // invalid message parameter type
    const responseInvalidMessageType = await snap.request({
      method: 'signMessage',
      params: { message: 1 },
    });
    assertInvalidMessage(responseInvalidMessageType);
  });

  function verifySignature(
    signatureHex: string,
    rawMessage: string,
    publicKeyHex: string,
  ) {
    // remove the starting 0x
    const signatureHexWithout0x = signatureHex.slice(2);
    const publicKeyWithout0x = publicKeyHex.slice(2);

    const signature = secp256k1.Signature.fromCompact(signatureHexWithout0x);
    const shaMessage = sha256(rawMessage);
    const publicKey = hexToBytes(publicKeyWithout0x);

    return secp256k1.verify(signature, shaMessage, publicKey);
  }
});

describe('onRpcRequest - bad request', () => {
  it('should fail if calling a rpc method that does not exist', async () => {
    const snap = await installSnap();

    const badRequestMethod = await snap.request({
      method: 'someFakeMethod',
    });
    expect(badRequestMethod).toRespondWithError({
      code: -32601,
      message: 'The method does not exist / is not available.',
      data: {
        cause: null,
        method: 'someFakeMethod',
      },
      stack: expect.any(String),
    });
  });
});
