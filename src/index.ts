import { rpcErrors } from '@metamask/rpc-errors';
import type { OnRpcRequestHandler } from '@metamask/snaps-sdk';
import { z } from 'zod';

import {
  getPublicEntropyKey,
  getAllPublicEntropyKeys,
  signMessageWithEntropyKey,
} from './entropy-keys';

const GetPublicEntropyKeyParamsSchema = z.object({
  entropySourceId: z.string().optional(),
});

const SignMessageParamsSchema = z.object({
  message: z.string().startsWith('metamask:'),
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
 * Asserts the shape of the `getPublicKey` request.
 * @param params - Any method params to assert.
 * @returns {never} Returns nothing, but will throw error if params don't match what is required.
 */
function assertGetPublicKeyParams(
  params: unknown,
): asserts params is z.infer<typeof GetPublicEntropyKeyParamsSchema> {
  try {
    GetPublicEntropyKeyParamsSchema.parse(params);
  } catch {
    throw rpcErrors.invalidParams({
      message:
        '`getPublicKey`, must take an optional `entropySourceId` parameter',
    });
  }
}

export const onRpcRequest: OnRpcRequestHandler = async ({ request }) => {
  switch (request.method) {
    case 'getPublicKey': {
      const { params } = request;

      if (!params) {
        return getPublicEntropyKey();
      }

      assertGetPublicKeyParams(params);
      const { entropySourceId } = params;
      return getPublicEntropyKey(entropySourceId);
    }
    case 'getAllPublicKeys': {
      return getAllPublicEntropyKeys();
    }
    case 'signMessage': {
      const { params } = request;
      assertSignMessageParams(params);
      const { message } = params;
      return await signMessageWithEntropyKey(message);
    }
    default:
      throw rpcErrors.methodNotFound({
        data: { method: request.method },
      });
  }
};
