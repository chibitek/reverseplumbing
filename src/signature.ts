// Embedded code signature reader. Answers the question otool does not: what is
// this binary allowed to do on the machine, and who vouched for it.
// Parsing only. Nothing here verifies a signature cryptographically or checks a
// certificate chain against Apple's roots; see the limits note in the tool text.
import { createHash } from 'node:crypto';
import { readRegion } from './inspect.js';
import { parsePlist, type PlistDict } from './plist.js';

const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY = 0xfade_0c02;
const CSMAGIC_ENTITLEMENTS = 0xfade_7171;
const CSMAGIC_DER_ENTITLEMENTS = 0xfade_7172;
const CSMAGIC_BLOBWRAPPER = 0xfade_0b01;
const CSMAGIC_REQUIREMENTS = 0xfade_0c01;

// Code-signing flags that change what the kernel will allow at runtime.
const CS_FLAGS: [number, string][] = [[0x1, 'valid'], [0x2, 'adhoc'], [0x4, 'getTaskAllow'], [0x10, 'forcedLibraryValidation'],
  [0x100, 'hard'], [0x200, 'kill'], [0x400, 'checkExpiration'], [0x800, 'restrict'], [0x1000, 'enforcement'],
  [0x2000, 'requireLibraryValidation'], [0x4000, 'entitlementsValidated'], [0x10000, 'hardenedRuntime'], [0x20000, 'linkerSigned']];
const EXEC_SEG_FLAGS: [number, string][] = [[0x1, 'mainBinary'], [0x10, 'allowUnsigned'], [0x20, 'debugger'],
  [0x40, 'jit'], [0x80, 'skipLibraryValidation'], [0x100, 'canLoadCdHash'], [0x200, 'canExecCdHash']];
const HASH_TYPES: Record<number, string> = { 1: 'sha1', 2: 'sha256', 3: 'sha256-truncated', 4: 'sha384', 5: 'sha512' };

const names = (table: [number, string][], value: number) => table.filter(([bit]) => value & bit).map(([, name]) => name);

function parseCodeDirectory(blob: Buffer) {
  if (blob.length < 44) throw new Error('Truncated CodeDirectory.');
  const version = blob.readUInt32BE(8);
  const flags = blob.readUInt32BE(12);
  const identOffset = blob.readUInt32BE(20);
  const hashType = blob.readUInt8(37);
  // The CodeDirectory grew over time; each field only exists from its version on.
  const teamOffset = version >= 0x2_0200 ? blob.readUInt32BE(48) : 0;
  const execSegFlags = version >= 0x2_0400 && blob.length >= 88 ? Number(blob.readBigUInt64BE(80)) : 0;

  const cString = (at: number) => {
    if (at < 44 || at >= blob.length) return null;
    const end = blob.indexOf(0, at);
    return blob.subarray(at, end < 0 ? blob.length : end).toString('utf8');
  };
  // The cdhash every Apple tool quotes is the first 20 bytes of the digest of
  // this whole blob, taken with the directory's own hash algorithm.
  const algorithm = hashType === 1 ? 'sha1' : hashType === 4 ? 'sha384' : hashType === 5 ? 'sha512' : 'sha256';
  return {
    identifier: cString(identOffset),
    teamId: teamOffset ? cString(teamOffset) : null,
    cdHash: createHash(algorithm).update(blob).digest('hex').slice(0, 40),
    hashType: HASH_TYPES[hashType] ?? `0x${hashType.toString(16)}`,
    hashSize: blob.readUInt8(36),
    pageSize: blob.readUInt8(39) ? 1 << blob.readUInt8(39) : 0,
    codeLimit: blob.readUInt32BE(32),
    codeSlots: blob.readUInt32BE(28),
    version: `0x${version.toString(16)}`,
    flags: `0x${flags.toString(16)}`,
    flagNames: names(CS_FLAGS, flags),
    hardenedRuntime: Boolean(flags & 0x10000),
    adHoc: Boolean(flags & 0x2),
    executableSegmentFlags: names(EXEC_SEG_FLAGS, execSegFlags),
  };
}

/** Parse the SuperBlob a linker leaves at the LC_CODE_SIGNATURE offset. */
export function inspectSignatureBlob(blob: Buffer, sliceBytes?: number) {
  if (blob.length < 12 || blob.readUInt32BE(0) !== CSMAGIC_EMBEDDED_SIGNATURE) {
    throw new Error('Expected an embedded code signature SuperBlob.');
  }
  const count = blob.readUInt32BE(8);
  if (count > 64 || 12 + count * 8 > blob.length) throw new Error('Invalid code signature blob index.');

  let directory: ReturnType<typeof parseCodeDirectory> | null = null;
  let entitlements: PlistDict | null = null;
  let entitlementsUnreadable = false;
  let derEntitlementBytes = 0;
  let cmsBytes = 0;
  let hasRequirements = false;
  let alternateDirectories = 0;

  for (let i = 0; i < count; i++) {
    const at = blob.readUInt32BE(12 + i * 8 + 4);
    if (at + 8 > blob.length) throw new Error('Code signature blob offset out of range.');
    const magic = blob.readUInt32BE(at);
    const length = blob.readUInt32BE(at + 4);
    if (length < 8 || at + length > blob.length) throw new Error('Code signature blob length out of range.');
    const body = blob.subarray(at, at + length);
    if (magic === CSMAGIC_CODEDIRECTORY) {
      if (directory) alternateDirectories++;
      else directory = parseCodeDirectory(body);
    } else if (magic === CSMAGIC_ENTITLEMENTS) {
      // An entitlements blob is an XML plist the signer embedded; it is metadata, not capture data.
      try { entitlements = parsePlist(body.subarray(8)); } catch { entitlementsUnreadable = true; }
    } else if (magic === CSMAGIC_DER_ENTITLEMENTS) derEntitlementBytes = length - 8;
    else if (magic === CSMAGIC_BLOBWRAPPER) cmsBytes = length - 8;
    else if (magic === CSMAGIC_REQUIREMENTS) hasRequirements = true;
  }
  if (!directory) throw new Error('Code signature carries no CodeDirectory.');

  return {
    ...directory,
    signedBy: cmsBytes ? 'developer-certificate' : directory.adHoc ? 'ad-hoc' : 'none',
    cmsBytes,
    // A codeLimit short of the slice means bytes past it are outside the seal.
    sealsWholeSlice: sliceBytes === undefined ? null : directory.codeLimit >= sliceBytes - (blob.length + 16),
    hasRequirements,
    derEntitlementBytes,
    alternateDirectories,
    entitlements,
    entitlementsUnreadable,
    limits: 'Structural parse only. The CMS signature, certificate chain and page hashes are not verified here.',
  };
}

/** Locate and read the signature blob of one Mach-O slice. */
export async function readSignature(path: string, roots: string[], at: { offset: number; size: number }, sliceBytes?: number) {
  return inspectSignatureBlob(await readRegion(path, roots, at.offset, at.size), sliceBytes);
}
