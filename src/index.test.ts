import { installSnap } from '@metamask/snaps-jest';
import { hexToBytes } from '@noble/ciphers/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

describe('onRpcRequest - getPublicKey', () => {
  it('should return this snaps public key', async () => {
    const snap = await installSnap();
    const response = await snap.request({
      method: 'getPublicKey',
    });

    // We cant really test/mock the returned private key, so we can only test the "knowns" features of the public key
    // E.g. length = 68 chars
    // E.g. starts with '0x'
    const result = 'result' in response.response && response.response.result;
    expect(result?.toString().length).toBe(68);
    expect(result?.toString().startsWith('0x')).toBe(true);
  });
});

describe('onRpcRequest - signMessage', () => {
  it('should return a signature that can be verified', async () => {
    const snap = await installSnap();
    const MESSAGE = 'metamask:hello world';

    // Arrange - get public key
    const publicKeyResponse = await snap.request({
      method: 'getPublicKey',
    });
    const publicKey = ('result' in publicKeyResponse.response &&
      publicKeyResponse.response.result?.toString()) as string;

    // Act - create signature
    const signatureResponse = await snap.request({
      method: 'signMessage',
      params: { message: MESSAGE },
    });
    const signature = ('result' in signatureResponse.response &&
      signatureResponse.response.result?.toString()) as string;

    // Assert - validate signature
    expect(signature).toBeDefined();
    expect(verifySignature(signature, MESSAGE, publicKey)).toBe(true);
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
