import { base64ToBytes, bytesToHex } from '@metamask/utils';

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

  it('decrypts static message', () => {
    const receiverSecret = 'CyTDtSMUSxJ8wQ5Ht7fvko2frSuEEE9Srs5hZ/IODQ4=';
    const encrypted = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'EzjiHlL/0A7lViaG2OR1loa4Vu55vjKP',
      ephemPublicKey: 'EkLpuBHg/hY72uCVOzFFxM4ku2RRhjwn2rNtQETtMiI=',
      ciphertext: 'SOLw4OmDAhhQJf20Wk9uQbe60x1XpZIwYeMU',
    };

    const decrypted = ERC1024.decrypt(encrypted, base64ToBytes(receiverSecret));
    expect(decrypted).toBe('hello world');

    const decryptedUsingHexKey = ERC1024.decrypt(
      encrypted,
      bytesToHex(base64ToBytes(receiverSecret)),
    );
    expect(decryptedUsingHexKey).toBe('hello world');
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

  it('rejects unknown version', () => {
    const receiverSecret = base64ToBytes(
      'CyTDtSMUSxJ8wQ5Ht7fvko2frSuEEE9Srs5hZ/IODQ4=',
    );
    const encrypted = {
      version: 'ed25519-xsalsa20-poly1305',
    };
    expect(() => ERC1024.decrypt(encrypted as any, receiverSecret)).toThrow(
      'Encryption type/version not supported.',
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
      ciphertext: 'corruptedhhQJf20Wk9uQbe60x1XpZIwYeMU',
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
      nonce: 'WRONGlL/0A7lViaG2OR1loa4Vu55vjKP',
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
      nonce: 'WRONGGGG',
      ephemPublicKey: 'EkLpuBHg/hY72uCVOzFFxM4ku2RRhjwn2rNtQETtMiI=',
      ciphertext: 'SOLw4OmDAhhQJf20Wk9uQbe60x1XpZIwYeMU',
    };
    expect(() => ERC1024.decrypt(encrypted as any, receiverSecret)).toThrow(
      'Uint8Array expected of length 24, not of length=6',
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
      ephemPublicKey: 'corruptedhY72uCVOzFFxM4ku2RRhjwn2rNtQETtMiI=',
      ciphertext: 'SOLw4OmDAhhQJf20Wk9uQbe60x1XpZIwYeMU',
    };
    expect(() => ERC1024.decrypt(encrypted as any, receiverSecret)).toThrow(
      'invalid tag',
    );
  });
  it('fails decryption with missing ephemKey', () => {
    const receiverSecret = base64ToBytes(
      'CyTDtSMUSxJ8wQ5Ht7fvko2frSuEEE9Srs5hZ/IODQ4=',
    );
    const encrypted = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: 'EzjiHlL/0A7lViaG2OR1loa4Vu55vjKP',
      ciphertext: 'SOLw4OmDAhhQJf20Wk9uQbe60x1XpZIwYeMU',
    };
    expect(() => ERC1024.decrypt(encrypted as any, receiverSecret)).toThrow(
      'Value must be a string.',
    );
  });
});
