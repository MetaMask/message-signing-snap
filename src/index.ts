import { rpcErrors } from '@metamask/rpc-errors';
import type { OnRpcRequestHandler } from '@metamask/snaps-sdk';
import { z } from 'zod';

import {
  decryptMessage,
  getEncryptionPublicKey,
  getPublicEntropyKey,
  signMessageWithEntropyKey,
} from './entropy-keys';

const SignMessageParamsSchema = z.object({
  message: z.string().startsWith('metamask:'),
});

const DecryptMessageParamsSchema = z.object({
  data: z.object({
    version: z.string().regex(/^x25519-xsalsa20-poly1305$/u),
    nonce: z.string().length(32).base64(), // 24 bytes, base64 encoded
    ephemPublicKey: z.string().length(44).base64(), // 32 bytes, base64 encoded
    ciphertext: z.string().base64(),
  }),
});

/**
 * Asserts the shape of the `signMessage` request.
 * @param params - Any method params to assert.
 * @returns {never} Returns nothing, but will throw error if params don't match what is required.
 */
function assertSignMessageParams(
  params: unknown,
): asserts params is z.infer<typeof SignMessageParamsSchema> {
  try {
    SignMessageParamsSchema.parse(params);
  } catch {
    throw rpcErrors.invalidParams({
      message:
        '`signMessage`, must take a `message` parameter that must begin with `metamask:`',
    });
  }
}

/**
 * Asserts the shape of the `decryptMessage` request matches the expected {data: Eip1024EncryptedData}.
 * @param params - The input params to assert.
 * @returns {never} Returns nothing, but will throw error if params don't match what is required.
 */
function assertDecryptMessageParams(
  params: unknown,
): asserts params is z.infer<typeof DecryptMessageParamsSchema> {
  try {
    DecryptMessageParamsSchema.parse(params);
  } catch (error: any) {
    throw rpcErrors.invalidParams({
      message:
        '`decryptMessage`, must take a `data` parameter that must match the Eip1024EncryptedData schema',
    });
  }
}

export const onRpcRequest: OnRpcRequestHandler = async ({ request }) => {
  switch (request.method) {
    case 'getPublicKey': {
      return getPublicEntropyKey();
    }
    case 'signMessage': {
      const { params } = request;
      assertSignMessageParams(params);
      const { message } = params;
      return await signMessageWithEntropyKey(message);
    }
    case 'getEncryptionPublicKey': {
      return getEncryptionPublicKey();
    }
    case 'decryptMessage': {
      const { params } = request;
      assertDecryptMessageParams(params);
      const { data } = params;
      return await decryptMessage(data);
    }
    default:
      throw rpcErrors.methodNotFound({
        data: { method: request.method },
      });
  }
};
