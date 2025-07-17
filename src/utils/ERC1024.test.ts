import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  hexToBytes,
} from '@metamask/utils';
import { x25519 } from '@noble/curves/ed25519';

import { ERC1024 } from './ERC1024';
import { nacl } from './nacl';

describe('successfully', () => {
  it('encrypts to public key', () => {
    const receiverKeyPair = nacl.box.keyPair();

    const message = 'hello world';
    const encrypted = ERC1024.encrypt(receiverKeyPair.publicKey, message);
    expect(encrypted.version).toBe('x25519-xsalsa20-poly1305');
    expect(encrypted.nonce).toBeDefined();
    expect(encrypted.ephemPublicKey).toBeDefined();
    expect(encrypted.ciphertext).toBeDefined();
    expect(base64ToBytes(encrypted.nonce)).toHaveLength(24);
    expect(base64ToBytes(encrypted.ephemPublicKey)).toHaveLength(32);
  });

  // see test cases in https://github.com/ethereum/EIPs/pull/1098
  it('generates expected keys', () => {
    const receiverSecret =
      '7e5374ec2ef0d91761a6e72fdf8f6ac665519bfdf6da0a2329cf0d804514b816';
    const receiverPublicKey = bytesToBase64(
      x25519.getPublicKey(hexToBytes(receiverSecret)),
    );
    expect(receiverPublicKey).toBe(
      'C5YMNdqE4kLgxQhJO1MfuQcHP5hjVSXzamzd/TxlR0U=',
    );
  });

  // see test cases in https://github.com/ethereum/EIPs/pull/1098
  it('decrypts static message', () => {
    const receiverSecretKey = hexToBytes(
      '7e5374ec2ef0d91761a6e72fdf8f6ac665519bfdf6da0a2329cf0d804514b816',
    );
    const encryptedData = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: '1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej',
      ephemPublicKey: 'FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ=',
      ciphertext: 'f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy',
    };
    const expectedDecryptedMessage = 'My name is Satoshi Buterin';
    const decrypted = ERC1024.decrypt(encryptedData, receiverSecretKey);
    expect(decrypted).toBe(expectedDecryptedMessage);
  });

  it('encrypts to public key hex', () => {
    const receiverKeyPair = nacl.box.keyPair();

    const message = 'hello world';
    const encrypted = ERC1024.encrypt(
      bytesToHex(receiverKeyPair.publicKey),
      message,
    );
    expect(encrypted.version).toBe('x25519-xsalsa20-poly1305');
    expect(encrypted.nonce).toBeDefined();
    expect(encrypted.ephemPublicKey).toBeDefined();
    expect(encrypted.ciphertext).toBeDefined();
    expect(base64ToBytes(encrypted.nonce)).toHaveLength(24);
    expect(base64ToBytes(encrypted.ephemPublicKey)).toHaveLength(32);
  });

  it('encrypts and decrypts successfully', () => {
    const receiverKeyPair = nacl.box.keyPair();
    const message = 'hello world';
    const encrypted = ERC1024.encrypt(receiverKeyPair.publicKey, message);
    const decrypted = ERC1024.decrypt(encrypted, receiverKeyPair.secretKey);
    expect(decrypted).toBe('hello world');
  });
});

describe('errors:', () => {
  it('rejects null message on encryption', () => {
    const receiverKeyPair = nacl.box.keyPair();
    const message = null;
    expect(() =>
      ERC1024.encrypt(receiverKeyPair.publicKey, message as any),
    ).toThrow('string expected');
  });

  it('rejects unknown version for encryption', () => {
    expect(() =>
      ERC1024.encrypt(new Uint8Array(), 'dontcare', 'bad version'),
    ).toThrow('Encryption type/version not supported bad version');
  });

  it('rejects unknown version for decryption', () => {
    const encrypted = {
      version: 'bad version',
    };
    expect(() => ERC1024.decrypt(encrypted as any, new Uint8Array())).toThrow(
      'Encryption type/version not supported (bad version).',
    );
  });

  it('fails decryption with corrupted data', () => {
    const receiverSecret = base64ToBytes(
      'CyTDtSMUSxJ8wQ5Ht7fvko2frSuEEE9Srs5hZ/IODQ4=',
    );
    const encrypted = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'EzjiHlL/0A7lViaG2OR1loa4Vu55vjKP',
      ephemPublicKey: 'EkLpuBHg/hY72uCVOzFFxM4ku2RRhjwn2rNtQETtMiI=',
      ciphertext: 'corrupted++QJf20Wk9uQbe60x1XpZIwYeMU',
    };
    expect(() => ERC1024.decrypt(encrypted as any, receiverSecret)).toThrow(
      'invalid tag',
    );
  });

  it('fails decryption with corrupted data length', () => {
    const receiverSecret = base64ToBytes(
      'CyTDtSMUSxJ8wQ5Ht7fvko2frSuEEE9Srs5hZ/IODQ4=',
    );
    const encrypted = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'EzjiHlL/0A7lViaG2OR1loa4Vu55vjKP',
      ephemPublicKey: 'EkLpuBHg/hY72uCVOzFFxM4ku2RRhjwn2rNtQETtMiI=',
      ciphertext: 'corruptedU',
    };
    expect(() => ERC1024.decrypt(encrypted as any, receiverSecret)).toThrow(
      'padding: invalid, string should have whole number of bytes',
    );
  });

  it('fails decryption with wrong nonce', () => {
    const receiverSecret = base64ToBytes(
      'CyTDtSMUSxJ8wQ5Ht7fvko2frSuEEE9Srs5hZ/IODQ4=',
    );
    const encrypted = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'WRONG///0A7lViaG2OR1loa4Vu55vjKP',
      ephemPublicKey: 'EkLpuBHg/hY72uCVOzFFxM4ku2RRhjwn2rNtQETtMiI=',
      ciphertext: 'SOLw4OmDAhhQJf20Wk9uQbe60x1XpZIwYeMU',
    };
    expect(() => ERC1024.decrypt(encrypted as any, receiverSecret)).toThrow(
      'invalid tag',
    );
  });

  it('fails decryption with wrong nonce length', () => {
    const receiverSecret = base64ToBytes(
      'CyTDtSMUSxJ8wQ5Ht7fvko2frSuEEE9Srs5hZ/IODQ4=',
    );
    const encrypted = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'WRONG+length',
      ephemPublicKey: 'EkLpuBHg/hY72uCVOzFFxM4ku2RRhjwn2rNtQETtMiI=',
      ciphertext: 'SOLw4OmDAhhQJf20Wk9uQbe60x1XpZIwYeMU',
    };
    expect(() => ERC1024.decrypt(encrypted as any, receiverSecret)).toThrow(
      'Uint8Array expected of length 24, got length=9',
    );
  });

  it('fails decryption with wrong nonce encoding', () => {
    const receiverSecret = base64ToBytes(
      'CyTDtSMUSxJ8wQ5Ht7fvko2frSuEEE9Srs5hZ/IODQ4=',
    );
    const encrypted = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: '0x WRONG encoding',
      ephemPublicKey: 'EkLpuBHg/hY72uCVOzFFxM4ku2RRhjwn2rNtQETtMiI=',
      ciphertext: 'SOLw4OmDAhhQJf20Wk9uQbe60x1XpZIwYeMU',
    };
    expect(() => ERC1024.decrypt(encrypted as any, receiverSecret)).toThrow(
      'padding: invalid, string should have whole number of bytes',
    );
  });

  it('fails decryption with missing nonce', () => {
    const receiverSecret = base64ToBytes(
      'CyTDtSMUSxJ8wQ5Ht7fvko2frSuEEE9Srs5hZ/IODQ4=',
    );
    const encrypted = {
      version: 'x25519-xsalsa20-poly1305',
      ephemPublicKey: 'EkLpuBHg/hY72uCVOzFFxM4ku2RRhjwn2rNtQETtMiI=',
      ciphertext: 'SOLw4OmDAhhQJf20Wk9uQbe60x1XpZIwYeMU',
    };
    expect(() => ERC1024.decrypt(encrypted as any, receiverSecret)).toThrow(
      'Value must be a string.',
    );
  });

  it('fails decryption with corrupted ephemKey', () => {
    const receiverSecret = base64ToBytes(
      'CyTDtSMUSxJ8wQ5Ht7fvko2frSuEEE9Srs5hZ/IODQ4=',
    );
    const encrypted = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'EzjiHlL/0A7lViaG2OR1loa4Vu55vjKP',
      ephemPublicKey: 'corrupted++72uCVOzFFxM4ku2RRhjwn2rNtQETtMiI=',
      ciphertext: 'SOLw4OmDAhhQJf20Wk9uQbe60x1XpZIwYeMU',
    };
    expect(() => ERC1024.decrypt(encrypted as any, receiverSecret)).toThrow(
      'invalid tag',
    );
  });

  it('fails decryption with bad private key encoding', () => {
    expect(() =>
      ERC1024.decrypt(
        { version: 'x25519-xsalsa20-poly1305' } as any,
        '0x bad encoding',
      ),
    ).toThrow('Bad private key');
  });

  it('fails decryption with missing ephemKey', () => {
    const encrypted = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'EzjiHlL/0A7lViaG2OR1loa4Vu55vjKP',
      ciphertext: 'SOLw4OmDAhhQJf20Wk9uQbe60x1XpZIwYeMU',
    };
    expect(() => ERC1024.decrypt(encrypted as any, new Uint8Array())).toThrow(
      'Value must be a string.',
    );
  });

  it('fails encryption with bad public key encoding', () => {
    expect(() => ERC1024.encrypt('bad encoding' as any, 'nothing')).toThrow(
      'Bad public key',
    );
  });
});
