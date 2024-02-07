import { remove0x } from '@metamask/utils';
import { hexToBytes, bytesToHex } from '@noble/ciphers/utils';

/**
 * Converts a string address to bytes.
 * @param address - String/Hex address.
 * @returns Address Byte Array.
 */
export function addressToBytes(address: string) {
  return hexToBytes(remove0x(address));
}

/**
 * Converts an array of bytes to an address.
 * @param bytes - Address Byte Array.
 * @returns Address Hex String.
 */
export function bytesToAddress(bytes: Uint8Array) {
  return `0x${bytesToHex(bytes)}`;
}
