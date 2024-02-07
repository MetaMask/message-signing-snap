import { addressToBytes, bytesToAddress } from './address-conversion';

const MOCK_ADDRESS = '0x1234567890abcdef';
const MOCK_BYTES = new Uint8Array([18, 52, 86, 120, 144, 171, 205, 239]);

describe('address-conversion.ts - addressToBytes()', () => {
  it('should convert address to bytes', () => {
    expect(addressToBytes(MOCK_ADDRESS)).toStrictEqual(MOCK_BYTES);
  });
});

describe('address-conversion.ts - bytesToAddress()', () => {
  it('should convert bytes to address', () => {
    expect(bytesToAddress(MOCK_BYTES)).toStrictEqual(MOCK_ADDRESS);
  });
});
