import { getPublicEntropyKey, signMessageWithEntropyKey } from './entropy-keys';

const MOCK_PRIVATE_KEY =
  '0xec180de430cef919666c2009b91ca3d3b7f6c471136abc9937fa40b89357bbb9';

const MOCK_PUBLIC_KEY =
  '0x02c291ee55d10abcc46de22b775cb0782b06f386ced8b0d0fccb8007a686bbddad';

describe('getPublicEntropyKey() tests', () => {
  it('should return a public key from a known private key', async () => {
    mockSnapGetEntropy();

    const address = await getPublicEntropyKey();
    expect(address).toBe(MOCK_PUBLIC_KEY);
  });
});

describe('signMessageWithEntropyKey() tests', () => {
  it('should sign a message with a known private key', async () => {
    mockSnapGetEntropy();

    const signature = await signMessageWithEntropyKey('hello world');
    const EXPECTED_SIGNATURE =
      '0x9499d23f16a2fd8511064f7622e0b0c8430d03fd65fda06c85510dfa33e86490781f39d54e880acb76a2ac5a241ba9e68a6a5bee88960ff918c82a54f002492b';
    expect(signature).toBe(EXPECTED_SIGNATURE);
  });
});

function mockSnapGetEntropy() {
  const mockSnapRequest = jest
    .fn()
    .mockImplementation(async (r: { method: string }) => {
      if (r.method === 'snap_getEntropy') {
        return MOCK_PRIVATE_KEY; // return private key
      }

      throw new Error(`TEST ENV - Snap Request was not mocked: ${r.method}`);
    });

  (global as any).snap = {
    request: mockSnapRequest,
  };
}
