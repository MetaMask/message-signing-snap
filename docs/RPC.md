# RPC Methods

### getPublicKey

Returns the public key for the deterministically random private key inside the snap.

> **Note:** Public keys and signatures are domain-specific. The snap uses the origin of the requesting site as a salt when generating entropy, which means the same user will have different public keys and signatures across different websites. This prevents cross-site correlation of user identities. However, MetaMask internal origins (like portfolio.metamask.io, docs.metamask.io, developer.metamask.io, and the extension itself) receive unsalted keys, allowing consistent identity across the MetaMask ecosystem.

#### Parameters

An object containing:

- `entropySourceId` - Optional. Used to select a particular entropy source. If not provided, the default entropy source is used. See [getAllPublicKeys](#getAllPublicKeys) for a list of available entropy sources and their corresponding public keys.

#### Returns

A 68 character hexadecimal public key (secp256k1 in compact form, prefixed with `0x`).

Example:

```ts
// `publicKey` is a hexadecimal string (including 0x), with length of 68.
const publicKey: string = await ethereum.request({
  method: 'wallet_invokeSnap',
  params: {
    snapId: 'npm:@metamask/message-signing-snap',
    request: {
      method: 'getPublicKey',
      params: {
        entropySourceId: '...', // optional
      },
    },
  },
});
```

### getAllPublicKeys

Returns an array of entropySource IDs and the corresponding public keys for them.

#### Parameters

- None

#### Returns

An array of `[EntropySourceId, string]` tuples, where the first element is the entropy source ID and the second element is the public key.

> **Note:** Public keys and signatures are domain-specific. The same rules apply to this method as to [getPublicKey](#getPublicKey).

Example:

```ts
const publicKeys: [] = await ethereum.request({
  method: 'wallet_invokeSnap',
  params: {
    snapId: 'npm:@metamask/message-signing-snap',
    request: {
      method: 'getAllPublicKeys',
    },
  },
});
```

### signMessage

Allows automatically signing specific messages, prefixed with `metamask:`.
The returned signature can be verified using the public key and the message. See an [example verification](verify-a-signature) or check out the snaps tests.

> **Note:** Public keys and signatures are domain-specific. The same rules apply to this method as to [getPublicKey](#getPublicKey).

#### Parameters

An object containing:

- `message` - The message that you are signing. The message must start with `metamask:`
- `entropySourceId` - Optional. Used to select a particular entropy source. If not provided, the default entropy source is used. See [getAllPublicKeys](#getAllPublicKeys) for a list of available entropy sources and their corresponding public keys.

#### Returns

A hexadecimal string signed message (signature).

You can see an [example below](#verify-a-signature) on how you can verify this signature.

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
        message: 'metamask:my message to sign',
        entropySourceId: '...', // optional
      },
    },
  },
});
```

#### Verify a signature

Example, how to verify a signature:

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
