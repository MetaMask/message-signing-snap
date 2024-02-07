# RPC Methods

### getPublicKey

Returns the public key for the deterministically random private key inside the snap.

#### Parameters

None

#### Returns

A 68 character hexadecimal public key.

Example:

```ts
// `publicKey` is a hexadecimal string (including 0x), with length of 68.
const publicKey: string = await ethereum.request({
  method: 'wallet_invokeSnap',
  params: {
    snapId: 'npm:@metamask/message-signing-snap',
    request: {
      method: 'getPublicKey',
    }
  }
})
```

### signMessage

Allows signing specific messages, tagged with `metamask:`, to be signed.

The returning signature can be verified using the public key. See an example verification in the snaps tests.

#### Parameters

An object containing:

- `message` - The message that you are signing. The message must start with `metamask:`

#### Returns

A hexadecimal string signed message (signature).

You can see an example test on how you can verify this signature (secp256k1 signature)

Example:

```ts
// `signature` is a  hexadecimal string (including 0x)
const signature: string = await ethereum.request({
  method: 'wallet_invokeSnap',
  params: {
    snapId: 'npm:@metamask/message-signing-snap',
    request: {
      method: 'signMessage',
      params: {
        message: 'metamask:my message to sign'
      }
    }
  }
})
```

Example how to verify signature:

```ts
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hexToBytes } from '@noble/ciphers/utils';
function verifySignature(
  signatureHex: string,
  rawMessage: string,
  publicKeyHex: string,
) {
  const signatureHexWithout0x = signatureHex.slice(2);
  const publicKeyWithout0x = publicKeyHex.slice(2);

  const signature = secp256k1.Signature.fromCompact(signatureHexWithout0x);
  const shaMessage = sha256(rawMessage);
  const publicKey = hexToBytes(publicKeyWithout0x);

  return secp256k1.verify(signature, shaMessage, publicKey);
}
```