// Application bundle reader. The binary says what code loads; the bundle says
// where the app updates itself from and what it asks the user for. On a Mac
// that update channel is the part worth reading before an app reaches a fleet.
import { join } from 'node:path';
import { readArtifact, listInRoot } from './inspect.js';
import { parsePlist, plistString, type PlistDict } from './plist.js';

const STAPLED_TICKET_MAGIC = 's8ch';

async function present(path: string, roots: string[]) {
  try { await readArtifact(path, roots); return true; } catch { return false; }
}

function sparkle(info: PlistDict) {
  const feedUrl = plistString(info, 'SUFeedURL');
  const configured = Object.keys(info).some(key => key.startsWith('SU'));
  if (!configured) return { framework: 'none-declared' as const };
  return {
    framework: 'sparkle' as const,
    feedUrl,
    // An update feed fetched over plaintext is the whole channel's weak point.
    feedOverHttps: feedUrl ? feedUrl.toLowerCase().startsWith('https://') : null,
    // With an EdDSA public key in the bundle, Sparkle refuses an update it cannot verify.
    updateSignaturePinned: typeof info.SUPublicEDKey === 'string' || typeof info.SUPublicDSAKeyFile === 'string',
    automaticChecks: info.SUEnableAutomaticChecks ?? null,
    automaticDownloads: info.SUAutomaticallyUpdate ?? null,
    checkIntervalSeconds: typeof info.SUScheduledCheckInterval === 'number' ? info.SUScheduledCheckInterval : null,
  };
}

export async function inspectBundle(path: string, roots: string[]) {
  const contents = join(path, 'Contents');
  const info = parsePlist(await readArtifact(join(contents, 'Info.plist'), roots));
  const executable = plistString(info, 'CFBundleExecutable');

  const ticket = await readArtifact(join(contents, 'CodeResources'), roots).catch(() => null);
  const frameworks = await listInRoot(join(contents, 'Frameworks'), roots).catch(() => []);

  return {
    bundle: {
      identifier: plistString(info, 'CFBundleIdentifier'),
      name: plistString(info, 'CFBundleName'),
      shortVersion: plistString(info, 'CFBundleShortVersionString'),
      version: plistString(info, 'CFBundleVersion'),
      minimumSystemVersion: plistString(info, 'LSMinimumSystemVersion'),
      executable,
      executablePath: executable ? join(contents, 'MacOS', executable) : null,
      infoKeys: Object.keys(info).length,
    },
    updates: sparkle(info),
    frameworks,
    // What the app will ask the user to hand over, declared up front.
    privacyUsage: Object.keys(info).filter(key => key.endsWith('UsageDescription')).sort(),
    appTransportSecurityConfigured: 'NSAppTransportSecurity' in info,
    signing: {
      resourceSeal: await present(join(contents, '_CodeSignature', 'CodeResources'), roots),
      stapledNotarizationTicket: ticket !== null && ticket.subarray(0, 4).toString('latin1') === STAPLED_TICKET_MAGIC,
      provisioningProfile: await present(join(contents, 'embedded.provisionprofile'), roots),
    },
    limits: 'Reads the bundle as files. Does not verify the resource seal, the ticket, or any signature.',
  };
}
