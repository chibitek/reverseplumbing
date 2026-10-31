// iOS application reader. An .ipa is a zip, so this walks the central
// directory and lifts out only the few members worth reading. The first thing
// it answers is whether the executable is FairPlay-encrypted, because that one
// bit decides whether anything else in the binary can be read at all: a build
// straight from Xcode is readable, the same app re-downloaded from the App
// Store is not.
import { inflateRawSync } from 'node:zlib';
import { artifactSize, fatSlicesOf, inspectMachO, machOCommands, readRegion } from './inspect.js';
import { parsePlist, plistString, type PlistDict } from './plist.js';
import { scanTextSections } from './strings.js';

const EOCD_SIGNATURE = 0x06054b50, CENTRAL_SIGNATURE = 0x02014b50, LOCAL_SIGNATURE = 0x04034b50;
const EOCD_BYTES = 22;
// The end-of-central-directory record sits last, behind a comment of at most 64 KiB.
const TAIL_BYTES = EOCD_BYTES + 0xffff;
const MAX_ENTRIES = 50_000;
export const MAX_MEMBER_BYTES = 32 * 1024 * 1024;
const FAT_MAGICS = [0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca];
const LC_ENCRYPTION_INFO = 0x21, LC_ENCRYPTION_INFO_64 = 0x2c;

export type ZipEntry = { name: string; method: number; compressedBytes: number; bytes: number; headerOffset: number };

export async function readCentralDirectory(path: string, roots: string[]) {
  const size = await artifactSize(path, roots);
  const tailBytes = Math.min(size, TAIL_BYTES);
  if (tailBytes < EOCD_BYTES) throw new Error('File is too small to be a zip archive.');
  const tail = await readRegion(path, roots, size - tailBytes, tailBytes);

  let at = -1;
  for (let i = tail.length - EOCD_BYTES; i >= 0; i--) {
    if (tail.readUInt32LE(i) === EOCD_SIGNATURE) { at = i; break; }
  }
  if (at < 0) throw new Error('No zip end-of-central-directory record.');

  const count = tail.readUInt16LE(at + 10);
  const dirBytes = tail.readUInt32LE(at + 12);
  const dirOffset = tail.readUInt32LE(at + 16);
  // ponytail: classic zip only. A zip64 archive (over 4 GiB, or more than
  // 65,535 members) fails here rather than being guessed at; read the zip64
  // locator the day a real .ipa needs it.
  if (count === 0xffff || dirBytes === 0xffffffff || dirOffset === 0xffffffff) {
    throw new Error('Zip64 archives are not supported by this reader.');
  }
  if (count > MAX_ENTRIES) throw new Error('Refusing an archive with more members than expected.');
  if (dirOffset + dirBytes > size) throw new Error('Zip central directory falls outside the file.');

  const dir = await readRegion(path, roots, dirOffset, dirBytes);
  const entries: ZipEntry[] = [];
  let cursor = 0;
  for (let i = 0; i < count; i++) {
    if (cursor + 46 > dir.length || dir.readUInt32LE(cursor) !== CENTRAL_SIGNATURE) {
      throw new Error('Malformed zip central directory.');
    }
    const nameBytes = dir.readUInt16LE(cursor + 28);
    const extraBytes = dir.readUInt16LE(cursor + 30);
    const commentBytes = dir.readUInt16LE(cursor + 32);
    entries.push({
      // A member name is a map key here and never a path we open, so a
      // traversing name cannot reach the filesystem.
      name: dir.subarray(cursor + 46, cursor + 46 + nameBytes).toString('utf8'),
      method: dir.readUInt16LE(cursor + 10),
      compressedBytes: dir.readUInt32LE(cursor + 20),
      bytes: dir.readUInt32LE(cursor + 24),
      headerOffset: dir.readUInt32LE(cursor + 42),
    });
    cursor += 46 + nameBytes + extraBytes + commentBytes;
  }
  return { size, entries, dirOffset };
}

/** Lift one member into memory. The local header repeats the name and extra lengths, and may disagree with the central one. */
export async function readMember(path: string, roots: string[], entry: ZipEntry) {
  if (entry.bytes > MAX_MEMBER_BYTES || entry.compressedBytes > MAX_MEMBER_BYTES) {
    throw new Error('Archive member is larger than this reader will load.');
  }
  const local = await readRegion(path, roots, entry.headerOffset, 30);
  if (local.readUInt32LE(0) !== LOCAL_SIGNATURE) throw new Error('Malformed zip local header.');
  const dataAt = entry.headerOffset + 30 + local.readUInt16LE(26) + local.readUInt16LE(28);
  const raw = await readRegion(path, roots, dataAt, entry.compressedBytes);
  if (entry.method === 0) return raw;
  if (entry.method !== 8) throw new Error('Unsupported zip compression method.');
  // maxOutputLength is what stops a member that claims to be small from inflating into the heap.
  return inflateRawSync(raw, { maxOutputLength: MAX_MEMBER_BYTES });
}

/** The slices of an in-memory Mach-O, thin or universal, in the shape the section scan wants. */
function slicesOf(binary: Buffer) {
  const fat = FAT_MAGICS.includes(binary.readUInt32BE(0));
  const regions = fat ? fatSlicesOf(binary) : [{ offset: 0, size: binary.length }];
  return { fat, slices: regions.map(region => ({ ...region, prefix: binary.subarray(region.offset, region.offset + region.size) })) };
}

/** FairPlay marks the encrypted region in a load command and leaves cryptid set once the Store has wrapped it. */
function encryption(prefix: Buffer) {
  for (const { kind, size, offset, read } of machOCommands(prefix)) {
    if ((kind !== LC_ENCRYPTION_INFO && kind !== LC_ENCRYPTION_INFO_64) || size < 20) continue;
    return { declared: true, encrypted: read(offset + 16) !== 0, regionOffset: read(offset + 8), regionBytes: read(offset + 12) };
  }
  return { declared: false, encrypted: false, regionOffset: 0, regionBytes: 0 };
}

/** The provisioning profile is CMS-wrapped around a plain XML plist. Read the plist, leave the signature alone. */
function provisioning(bytes: Buffer): PlistDict | null {
  const start = bytes.indexOf('<?xml');
  const end = bytes.indexOf('</plist>');
  if (start < 0 || end < start) return null;
  return parsePlist(bytes.subarray(start, end + 8));
}

function namesUnder(names: string[], pattern: RegExp) {
  return [...new Set(names.flatMap(name => pattern.exec(name)?.[1] ?? []))].sort();
}

export async function inspectIosApp(path: string, roots: string[], limit = 200) {
  const { size, entries } = await readCentralDirectory(path, roots);
  const appRoot = entries.map(entry => /^Payload\/[^/]+\.app\//.exec(entry.name)?.[0]).find(Boolean);
  if (!appRoot) throw new Error('No Payload/<name>.app directory in the archive.');
  const find = (name: string) => entries.find(entry => entry.name === name);

  const infoEntry = find(`${appRoot}Info.plist`);
  if (!infoEntry) throw new Error('No Info.plist in the application bundle.');
  const info = parsePlist(await readMember(path, roots, infoEntry));
  const executable = plistString(info, 'CFBundleExecutable');

  const profileEntry = find(`${appRoot}embedded.mobileprovision`);
  const profile = profileEntry ? provisioning(await readMember(path, roots, profileEntry)) : null;

  const inside = entries.filter(entry => entry.name.startsWith(appRoot)).map(entry => entry.name.slice(appRoot.length));
  const executableEntry = executable ? find(`${appRoot}${executable}`) : undefined;

  let binary: Awaited<ReturnType<typeof inspectMachO>> | null = null;
  let fairplay = null;
  let strings = null;
  let unread: string | null = executableEntry ? null : 'The bundle names no readable executable.';
  if (executableEntry) {
    try {
      const bytes = await readMember(path, roots, executableEntry);
      const { fat, slices } = slicesOf(bytes);
      binary = { ...inspectMachO(slices[0].prefix), universal: fat } as never;
      fairplay = encryption(slices[0].prefix);
      // Encrypted __TEXT holds ciphertext. Scanning it would return noise dressed as findings.
      if (fairplay.encrypted) unread = 'The executable is FairPlay-encrypted, so its text sections are ciphertext and were not scanned.';
      else strings = await scanTextSections(slices, async (offset, length) => bytes.subarray(offset, offset + length), limit);
    } catch (error) {
      unread = `The executable could not be read: ${(error as Error).message}`;
    }
  }

  return {
    archiveBytes: size,
    members: entries.length,
    app: {
      bundlePath: appRoot,
      identifier: plistString(info, 'CFBundleIdentifier'),
      name: plistString(info, 'CFBundleName'),
      displayName: plistString(info, 'CFBundleDisplayName'),
      shortVersion: plistString(info, 'CFBundleShortVersionString'),
      version: plistString(info, 'CFBundleVersion'),
      minimumOsVersion: plistString(info, 'MinimumOSVersion'),
      executable,
      builtWith: {
        sdk: plistString(info, 'DTSDKName'),
        platformVersion: plistString(info, 'DTPlatformVersion'),
        xcodeBuild: plistString(info, 'DTXcodeBuild'),
      },
      infoKeys: Object.keys(info).length,
    },
    // What the app will ask the user to hand over, and how it reaches the system, declared up front.
    privacyUsage: Object.keys(info).filter(key => key.endsWith('UsageDescription')).sort(),
    backgroundModes: 'UIBackgroundModes' in info,
    urlSchemesDeclared: 'CFBundleURLTypes' in info,
    appTransportSecurityConfigured: 'NSAppTransportSecurity' in info,
    structure: {
      appExtensions: namesUnder(inside, /^PlugIns\/([^/]+\.appex)\//),
      frameworks: namesUnder(inside, /^Frameworks\/([^/]+?)(?:\/|$)/),
      watchApps: namesUnder(inside, /^Watch\/([^/]+\.app)\//),
      resourceBundles: namesUnder(inside, /^([^/]+\.bundle)\//),
      compiledAssets: inside.includes('Assets.car'),
      debugSymbolsShipped: entries.some(entry => entry.name.startsWith('Symbols/')),
    },
    signing: {
      resourceSeal: Boolean(find(`${appRoot}_CodeSignature/CodeResources`)),
      provisioningProfile: Boolean(profileEntry),
      profile: profile && {
        appIdName: plistString(profile, 'AppIDName'),
        teamName: plistString(profile, 'TeamName'),
        created: plistString(profile, 'CreationDate'),
        expires: plistString(profile, 'ExpirationDate'),
        provisionsAllDevices: profile.ProvisionsAllDevices === true,
        deviceListPresent: 'ProvisionedDevices' in profile,
      },
    },
    binary,
    fairplay,
    strings,
    unread,
    limits: 'Reads the archive in place; nothing is extracted to disk and the application is not installed or launched. The code signature and the provisioning profile are parsed structurally, not verified.',
  };
}
