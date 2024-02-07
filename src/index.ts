import { rpcErrors } from '@metamask/rpc-errors';
import type { OnRpcRequestHandler } from '@metamask/snaps-sdk';
import { z } from 'zod';

import { getPublicEntropyKey, signMessageWithEntropyKey } from './entropy-keys';

const SignMessageParamsSchema = z.object({
  message: z.string().startsWith('metamask:'),
});

/**
 * Asserts the shape of the `signMessage` request.
 *
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
    default:
      throw rpcErrors.methodNotFound({
        data: { method: request.method },
      });
  }
};
