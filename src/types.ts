import type { EntropySource } from '@metamask/snaps-sdk';

export type EntropySourceId = EntropySource['id'];

export type EntropySourceIdSrpIdMap = [EntropySourceId, string][];
