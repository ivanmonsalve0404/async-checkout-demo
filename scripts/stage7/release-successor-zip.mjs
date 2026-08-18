import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { inflateRawSync } from 'node:zlib';

const MAX_ENTRIES = 4096;
const MAX_ENTRY_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;

export class Stage7ReleaseSuccessorZipError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseSuccessorZipError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseSuccessorZipError(code, cause === undefined ? undefined : { cause });
};

const crcTable = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) === 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});
const crc32 = (bytes) => {
  let value = 0xffffffff;
  for (const byte of bytes) value = crcTable[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
};

export const readReleaseSuccessorZipEntries = (archive) => {
  const bytes = Buffer.isBuffer(archive) ? Buffer.from(archive) : Buffer.from(archive ?? '');
  let eocd = -1;
  for (let offset = bytes.length - 22; offset >= Math.max(0, bytes.length - 65_557); offset -= 1) {
    if (bytes.readUInt32LE(offset) === 0x06054b50) {
      eocd = offset;
      break;
    }
  }
  if (
    eocd < 0 ||
    bytes.readUInt16LE(eocd + 4) !== 0 ||
    bytes.readUInt16LE(eocd + 6) !== 0 ||
    bytes.readUInt16LE(eocd + 8) !== bytes.readUInt16LE(eocd + 10) ||
    bytes.readUInt16LE(eocd + 10) < 1 ||
    bytes.readUInt16LE(eocd + 10) > MAX_ENTRIES ||
    eocd + 22 + bytes.readUInt16LE(eocd + 20) !== bytes.length
  ) {
    fail('E7_RELEASE_SUCCESSOR_ZIP_EOCD_INVALID');
  }
  const total = bytes.readUInt16LE(eocd + 10);
  const centralSize = bytes.readUInt32LE(eocd + 12);
  const centralOffset = bytes.readUInt32LE(eocd + 16);
  if (centralOffset + centralSize !== eocd) fail('E7_RELEASE_SUCCESSOR_ZIP_CENTRAL_INVALID');
  const entries = new Map();
  const caseFoldedNames = new Set();
  const localIntervals = [];
  let totalBytes = 0;
  let offset = centralOffset;
  for (let index = 0; index < total; index += 1) {
    if (offset + 46 > eocd || bytes.readUInt32LE(offset) !== 0x02014b50) {
      fail('E7_RELEASE_SUCCESSOR_ZIP_CENTRAL_INVALID');
    }
    const flags = bytes.readUInt16LE(offset + 8);
    const method = bytes.readUInt16LE(offset + 10);
    const expectedCrc = bytes.readUInt32LE(offset + 16);
    const compressedSize = bytes.readUInt32LE(offset + 20);
    const uncompressedSize = bytes.readUInt32LE(offset + 24);
    const nameLength = bytes.readUInt16LE(offset + 28);
    const extraLength = bytes.readUInt16LE(offset + 30);
    const commentLength = bytes.readUInt16LE(offset + 32);
    const externalAttributes = bytes.readUInt32LE(offset + 38);
    const localOffset = bytes.readUInt32LE(offset + 42);
    const end = offset + 46 + nameLength + extraLength + commentLength;
    const nameBytes = bytes.subarray(offset + 46, offset + 46 + nameLength);
    const name = nameBytes.toString('utf8');
    const segments = name.split('/');
    const normalizedName = name.normalize('NFC');
    const folded = normalizedName.toLocaleLowerCase('en-US');
    const unixMode = externalAttributes >>> 16;
    if (
      end > eocd ||
      name.length < 1 ||
      !Buffer.from(name, 'utf8').equals(nameBytes) ||
      name.includes('\\') ||
      name.startsWith('/') ||
      normalizedName !== name ||
      segments.some((segment) => segment === '' || segment === '.' || segment === '..') ||
      name.endsWith('/') ||
      entries.has(name) ||
      caseFoldedNames.has(folded) ||
      ![0, 0x0800].includes(flags) ||
      ![0, 8].includes(method) ||
      [compressedSize, uncompressedSize, localOffset].includes(0xffffffff) ||
      uncompressedSize < 1 ||
      uncompressedSize > MAX_ENTRY_BYTES ||
      (unixMode & 0o170000) === 0o120000 ||
      localOffset + 30 > centralOffset ||
      bytes.readUInt32LE(localOffset) !== 0x04034b50
    ) {
      fail('E7_RELEASE_SUCCESSOR_ZIP_ENTRY_INVALID');
    }
    const localFlags = bytes.readUInt16LE(localOffset + 6);
    const localMethod = bytes.readUInt16LE(localOffset + 8);
    const localCrc = bytes.readUInt32LE(localOffset + 14);
    const localCompressedSize = bytes.readUInt32LE(localOffset + 18);
    const localUncompressedSize = bytes.readUInt32LE(localOffset + 22);
    const localNameLength = bytes.readUInt16LE(localOffset + 26);
    const localExtraLength = bytes.readUInt16LE(localOffset + 28);
    const localName = bytes
      .subarray(localOffset + 30, localOffset + 30 + localNameLength)
      .toString('utf8');
    const localNameBytes = bytes.subarray(localOffset + 30, localOffset + 30 + localNameLength);
    const dataOffset = localOffset + 30 + localNameLength + localExtraLength;
    const dataEnd = dataOffset + compressedSize;
    if (
      localFlags !== flags ||
      localMethod !== method ||
      localCrc !== expectedCrc ||
      localCompressedSize !== compressedSize ||
      localUncompressedSize !== uncompressedSize ||
      localName !== name ||
      !localNameBytes.equals(nameBytes) ||
      dataEnd > centralOffset
    ) {
      fail('E7_RELEASE_SUCCESSOR_ZIP_LOCAL_ENTRY_INVALID');
    }
    let content;
    if (totalBytes + uncompressedSize > MAX_TOTAL_BYTES) {
      fail('E7_RELEASE_SUCCESSOR_ZIP_CONTENT_INVALID');
    }
    try {
      const compressed = bytes.subarray(dataOffset, dataEnd);
      content =
        method === 0
          ? Buffer.from(compressed)
          : inflateRawSync(compressed, { maxOutputLength: uncompressedSize });
    } catch (error) {
      fail('E7_RELEASE_SUCCESSOR_ZIP_DEFLATE_INVALID', error);
    }
    totalBytes += content.length;
    if (
      content.length !== uncompressedSize ||
      crc32(content) !== expectedCrc ||
      totalBytes > MAX_TOTAL_BYTES
    ) {
      fail('E7_RELEASE_SUCCESSOR_ZIP_CONTENT_INVALID');
    }
    entries.set(name, content);
    caseFoldedNames.add(folded);
    localIntervals.push([localOffset, dataEnd]);
    offset = end;
  }
  if (offset !== eocd) fail('E7_RELEASE_SUCCESSOR_ZIP_CENTRAL_INVALID');
  localIntervals.sort((left, right) => left[0] - right[0]);
  let expectedLocalOffset = 0;
  for (const [start, end] of localIntervals) {
    if (start !== expectedLocalOffset || end <= start) {
      fail('E7_RELEASE_SUCCESSOR_ZIP_LOCAL_RANGE_INVALID');
    }
    expectedLocalOffset = end;
  }
  if (expectedLocalOffset !== centralOffset) {
    fail('E7_RELEASE_SUCCESSOR_ZIP_LOCAL_RANGE_INVALID');
  }
  return entries;
};

export const exactReleaseSuccessorZipEntry = (archive, pathName, { onlyEntry = false } = {}) => {
  const entries = readReleaseSuccessorZipEntries(archive);
  if ((onlyEntry && entries.size !== 1) || !entries.has(pathName)) {
    fail('E7_RELEASE_SUCCESSOR_ZIP_REQUIRED_ENTRY_MISSING');
  }
  return Buffer.from(entries.get(pathName));
};

export const createReleaseSuccessorStoredZipFixture = (files) => {
  const entries = Object.entries(files);
  if (entries.length < 1 || entries.length > MAX_ENTRIES) {
    fail('E7_RELEASE_SUCCESSOR_ZIP_FIXTURE_INVALID');
  }
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  for (const [name, source] of entries) {
    const nameBytes = Buffer.from(name, 'utf8');
    const content = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '');
    if (nameBytes.length < 1 || content.length < 1) {
      fail('E7_RELEASE_SUCCESSOR_ZIP_FIXTURE_INVALID');
    }
    const checksum = crc32(content);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(content.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    localParts.push(local, nameBytes, content);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x0314, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(content.length, 20);
    central.writeUInt32LE(content.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE((0o100600 << 16) >>> 0, 38);
    central.writeUInt32LE(localOffset, 42);
    centralParts.push(central, nameBytes);
    localOffset += local.length + nameBytes.length + content.length;
  }
  const centralBytes = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBytes.length, 12);
  eocd.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localParts, centralBytes, eocd]);
};

export const selfTestReleaseSuccessorZip = () => {
  const valid = createReleaseSuccessorStoredZipFixture({
    'a.json': Buffer.from('{"a":1}\n'),
    'b.json': Buffer.from('{"b":2}\n'),
  });
  assert.equal(readReleaseSuccessorZipEntries(valid).size, 2);
  const locateCentral = (archive) => {
    for (let offset = 0; offset <= archive.length - 4; offset += 1) {
      if (archive.readUInt32LE(offset) === 0x02014b50) return offset;
    }
    return -1;
  };
  const descriptor = Buffer.from(valid);
  descriptor.writeUInt16LE(0x0008, 6);
  descriptor.writeUInt16LE(0x0008, locateCentral(descriptor) + 8);
  assert.throws(() => readReleaseSuccessorZipEntries(descriptor));
  const badCrc = Buffer.from(valid);
  badCrc.writeUInt32LE(0, locateCentral(badCrc) + 16);
  assert.throws(() => readReleaseSuccessorZipEntries(badCrc));
  const bomb = Buffer.from(valid);
  bomb.writeUInt32LE(MAX_ENTRY_BYTES + 1, 22);
  bomb.writeUInt32LE(MAX_ENTRY_BYTES + 1, locateCentral(bomb) + 24);
  assert.throws(() => readReleaseSuccessorZipEntries(bomb));
  const overlap = Buffer.from(valid);
  const firstCentral = locateCentral(overlap);
  const firstNameLength = overlap.readUInt16LE(firstCentral + 28);
  const firstExtraLength = overlap.readUInt16LE(firstCentral + 30);
  const firstCommentLength = overlap.readUInt16LE(firstCentral + 32);
  const secondCentral = firstCentral + 46 + firstNameLength + firstExtraLength + firstCommentLength;
  overlap.writeUInt32LE(0, secondCentral + 42);
  assert.throws(() => readReleaseSuccessorZipEntries(overlap));
  const caseFold = createReleaseSuccessorStoredZipFixture({
    'A.json': Buffer.from('{"a":1}\n'),
    'a.json': Buffer.from('{"a":2}\n'),
  });
  assert.throws(() => readReleaseSuccessorZipEntries(caseFold));
  const duplicateName = Buffer.from(valid);
  const duplicateFirstCentral = locateCentral(duplicateName);
  const duplicateFirstNameLength = duplicateName.readUInt16LE(duplicateFirstCentral + 28);
  const duplicateFirstExtraLength = duplicateName.readUInt16LE(duplicateFirstCentral + 30);
  const duplicateFirstCommentLength = duplicateName.readUInt16LE(duplicateFirstCentral + 32);
  const duplicateSecondCentral =
    duplicateFirstCentral +
    46 +
    duplicateFirstNameLength +
    duplicateFirstExtraLength +
    duplicateFirstCommentLength;
  const duplicateSecondLocal = duplicateName.readUInt32LE(duplicateSecondCentral + 42);
  duplicateName[duplicateSecondCentral + 46] = 'a'.charCodeAt(0);
  duplicateName[duplicateSecondLocal + 30] = 'a'.charCodeAt(0);
  assert.throws(() => readReleaseSuccessorZipEntries(duplicateName));
  const localSizeMismatch = Buffer.from(valid);
  localSizeMismatch.writeUInt32LE(localSizeMismatch.readUInt32LE(18) + 1, 18);
  assert.throws(() => readReleaseSuccessorZipEntries(localSizeMismatch));
  const localNameMismatch = Buffer.from(valid);
  localNameMismatch[30] = 'z'.charCodeAt(0);
  assert.throws(() => readReleaseSuccessorZipEntries(localNameMismatch));
  const dotAlias = createReleaseSuccessorStoredZipFixture({
    'a/./b.json': Buffer.from('{"a":1}\n'),
  });
  assert.throws(() => readReleaseSuccessorZipEntries(dotAlias));
  const emptySegment = createReleaseSuccessorStoredZipFixture({
    'a//b.json': Buffer.from('{"a":1}\n'),
  });
  assert.throws(() => readReleaseSuccessorZipEntries(emptySegment));
  const nonNfc = createReleaseSuccessorStoredZipFixture({
    'cafe\u0301.json': Buffer.from('{"a":1}\n'),
  });
  assert.throws(() => readReleaseSuccessorZipEntries(nonNfc));
  return { status: 'PASS', canaries: 11, externalRequests: 0 };
};
