// Ghidra detection and a basic headless function listing | Chibitek Engineering | 2026-10-24
// Ghidra is operator-installed only: never downloaded, updated or installed from here.
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { resolveInRoot } from './inspect.js';

export const SANDBOX_EXEC = '/usr/bin/sandbox-exec';
// Every Ghidra launch runs inside this profile, so the JVM and anything it loads cannot open a socket.
export const NO_NETWORK = '(version 1)(allow default)(deny network*)';
const TIMEOUT_MS = 600_000;
// Not named ListFunctions.java: Ghidra ships a script by that name which prompts for a file.
const SCRIPT = `import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
public class RPFunctions extends GhidraScript {
  @Override public void run() throws Exception {
    int count = 0;
    for (Function f : currentProgram.getFunctionManager().getFunctions(true)) { println("RP_FUNCTION " + f.getEntryPoint() + " " + f.getName()); count++; }
    println("RP_SUMMARY " + currentProgram.getLanguageID() + " " + count);
  }
}
`;

export type GhidraInstall = { headless: string; javaHome: string | null; version: string | null };

async function isFile(path: string) {
  try { return (await stat(path)).isFile(); } catch { return false; }
}

async function locate(candidate: string): Promise<GhidraInstall | null> {
  let launcher: string;
  try { launcher = await realpath(candidate); } catch { return null; }
  // Homebrew wraps the distribution in libexec/; a plain release zip does not.
  for (const home of [join(dirname(dirname(launcher)), 'libexec'), dirname(launcher)]) {
    const headless = join(home, 'support', 'analyzeHeadless');
    if (!(await isFile(headless))) continue;
    const props = await readFile(join(home, 'Ghidra', 'application.properties'), 'utf8').catch(() => '');
    const wrapper = await readFile(launcher, 'utf8').catch(() => '');
    return { headless, version: props.match(/^application\.version=(.+)$/m)?.[1].trim() ?? null,
      javaHome: wrapper.match(/JAVA_HOME:-([^}]+)/)?.[1] ?? null };
  }
  return null;
}

/** Looks at files only. Never launches Ghidra or its JVM. */
export async function detectGhidra(candidates: string[]) {
  for (const path of candidates) {
    const install = await locate(path);
    if (install) return { installed: true, path, ...install, launched: false };
  }
  return { installed: false, launched: false, note: 'Use an existing operator-installed Ghidra; nothing is downloaded or installed.' };
}

function launch(file: string, args: string[], env: NodeJS.ProcessEnv) {
  return new Promise<string>((resolve, reject) => {
    execFile(file, args, { env, timeout: TIMEOUT_MS, maxBuffer: 256 * 1024 * 1024 }, (error, stdout) => error ? reject(error) : resolve(stdout));
  });
}

/** Imports one in-root file into a throwaway project, auto-analyzes it, and lists the functions found. */
export async function analyzeWithGhidra(path: string, roots: string[], candidates: string[], limit = 200) {
  if (!Number.isInteger(limit) || limit < 1) throw new Error('limit must be a positive integer.');
  const artifact = await resolveInRoot(path, roots);
  if (!(await isFile(artifact))) throw new Error('Expected a file.');
  let install: GhidraInstall | null = null;
  for (const candidate of candidates) if ((install = await locate(candidate))) break;
  if (!install) throw new Error('Ghidra is not installed at the configured path.');
  const work = await mkdtemp(join(tmpdir(), 'rp-ghidra-'));
  try {
    await writeFile(join(work, 'RPFunctions.java'), SCRIPT);
    const env = { PATH: '/usr/bin:/bin', HOME: process.env.HOME, ...(install.javaHome ? { JAVA_HOME: install.javaHome } : {}) };
    const out = await launch(SANDBOX_EXEC, ['-p', NO_NETWORK, install.headless, work, 'rp', '-import', artifact,
      '-scriptPath', work, '-postScript', 'RPFunctions.java', '-deleteProject', '-readOnly'], env);
    const functions = [...out.matchAll(/RP_FUNCTION (\S+) (.+?) \(GhidraScript\)/g)].map(m => ({ address: m[1], name: m[2] }));
    const summary = out.match(/RP_SUMMARY (\S+) (\d+)/);
    if (!summary) throw new Error('Ghidra did not analyze the file.');
    return { ghidraVersion: install.version, loader: out.match(/Using Loader: (.+)/)?.[1].trim() ?? null,
      language: summary[1], functionCount: Number(summary[2]), functions: functions.slice(0, limit),
      sandbox: 'network denied', executed: false };
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
