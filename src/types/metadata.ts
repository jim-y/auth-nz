import { METADATA_LITERALS } from '../constants.ts';
import type { ObjectValues } from './helpers.ts';

export type MetadataLiteral = ObjectValues<typeof METADATA_LITERALS>;