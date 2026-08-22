import { Buffer } from 'node:buffer';
import { TextDecoder } from 'node:util';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';

const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const PUBLIC_CONFIG_KEYS = ['apiBaseUrl', 'productId', 'releaseId'];

const exactKeys = (value, keys) =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');

const bytes = (value) => (Buffer.isBuffer(value) ? value : Buffer.from(value ?? ''));

const decodeUtf8 = (value) => new TextDecoder('utf-8', { fatal: true }).decode(bytes(value));

export const exactReleaseIdentityMeta = (releaseId) =>
  `<meta name="stage7-release-id" content="${releaseId}">`;

export const validateIndexReleaseIdentity = ({ indexSource, releaseId }) => {
  if (!RELEASE_ID.test(releaseId ?? '')) return false;
  let indexHtml;
  try {
    indexHtml = decodeUtf8(indexSource);
  } catch {
    return false;
  }
  const marker = exactReleaseIdentityMeta(releaseId);
  return (
    [...indexHtml.matchAll(/stage7-release-id/giu)].length === 1 &&
    [...indexHtml.matchAll(/<meta\b[^>]*>/giu)].filter(([tag]) =>
      /\bstage7-release-id\b/iu.test(tag),
    ).length === 1 &&
    indexHtml.includes(marker)
  );
};

export const validatePublicConfigReleaseIdentity = ({ publicConfigSource, releaseId }) => {
  if (!RELEASE_ID.test(releaseId ?? '')) return false;
  let publicConfig;
  try {
    publicConfig = parseStrictJsonSource(bytes(publicConfigSource), { scanForbiddenData: false });
  } catch {
    return false;
  }
  return (
    exactKeys(publicConfig, PUBLIC_CONFIG_KEYS) &&
    publicConfig.apiBaseUrl === '/api/v1' &&
    publicConfig.productId === 'product-demo-001' &&
    publicConfig.releaseId === releaseId
  );
};

export const validatePublicReleaseIdentity = ({ indexSource, publicConfigSource, releaseId }) =>
  validateIndexReleaseIdentity({ indexSource, releaseId }) &&
  validatePublicConfigReleaseIdentity({ publicConfigSource, releaseId });
