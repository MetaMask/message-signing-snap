import { rpcErrors } from '@metamask/rpc-errors';
import type { OnRpcRequestHandler } from '@metamask/snaps-sdk';
import { z } from 'zod';

import {
  getAllPublicEntropyKeys,
  getPublicEntropyKey,
  signMessageWithEntropyKey,
} from './entropy-keys';

const GetPublicEntropyKeyParamsSchema = z.object({
  entropySourceId: z.string().optional(),
});

const SignMessageParamsSchema = z.object({
  message: z.string().startsWith('metamask:'),
  entropySourceId: z.string().optional(),
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

/**
 * Request origins that should not be salted.
 * @internal
 */
export const INTERNAL_ORIGINS = [
  'https://portfolio.metamask.io',
  'https://portfolio-builds.metafi-dev.codefi.network',
  'https://docs.metamask.io',
  'https://developer.metamask.io',
  '', // calls coming from the extension or mobile app will have an empty origin
];

/**
 * Creates a salt based on the origin.
 * Metamask internal origins should return `undefined`.
 * @param origin - The origin of the RPC request.
 * @returns The salt used to obtain a domain specific entropy.
 * @internal
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function getSaltByOrigin(origin: string): string | undefined {
  // TODO: use smarter matching here
  if (!origin || INTERNAL_ORIGINS.includes(origin)) {
    return undefined;
  }
  return origin;
}

export const onRpcRequest: OnRpcRequestHandler = async ({
  request,
  origin,
}) => {
  const salt = getSaltByOrigin(origin);
  switch (request.method) {
    case 'getPublicKey': {
      const { params } = request;

      if (!params) {
        return getPublicEntropyKey(undefined, salt);
      }

      assertGetPublicKeyParams(params);
      const { entropySourceId } = params;
      return getPublicEntropyKey(entropySourceId, salt);
    }
    case 'getAllPublicKeys': {
      return getAllPublicEntropyKeys(salt);
    }
    case 'signMessage': {
      const { params } = request;
      assertSignMessageParams(params);
      const { message, entropySourceId } = params;
      return await signMessageWithEntropyKey(message, entropySourceId, salt);
    }
    default:
      throw rpcErrors.methodNotFound({
        data: { method: request.method },
      });
  }
};
