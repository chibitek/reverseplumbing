// Authenticode reader: the WIN_CERTIFICATE table a signed PE carries, walked as DER. Reports who
// signed, with which certificates, the digest the signature claims and any timestamp. No signature,
// chain, revocation or trust check is made.
import { X509Certificate } from 'node:crypto';
import { digestRanges, loadPe } from './pe.js';

const MAX_CERT_TABLE = 16 * 1024 * 1024;
const MAX_NESTING = 8;
const OID: Record<string, string> = {
  '1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512', '1.2.840.113549.2.5': 'md5',
};
const SIGNED_DATA = '1.2.840.113549.1.7.2', SPC_INDIRECT_DATA = '1.3.6.1.4.1.311.2.1.4', NESTED = '1.3.6.1.4.1.311.2.4.1';
const COUNTER_SIGNATURE = '1.2.840.113549.1.9.6', RFC3161 = '1.3.6.1.4.1.311.3.3.1', SIGNING_TIME = '1.2.840.113549.1.9.5';
const TST_INFO = '1.2.840.113549.1.9.16.1.4';

type Node = { tag: number; start: number; end: number; whole: Buffer; body: Buffer };

/** One DER element at `at`. Indefinite (BER) lengths are refused. */
export function der(buf: Buffer, at: number): Node {
  const tag = buf[at];
  let length = buf[at + 1], start = at + 2;
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n < 1 || n > 4) throw new Error('Unsupported DER length.');
    length = buf.readUIntBE(start, n);
    start += n;
  }
  if (tag === undefined || start + length > buf.length) throw new Error('DER element runs past its parent.');
  return { tag, start, end: start + length, whole: buf.subarray(at, start + length), body: buf.subarray(start, start + length) };
}
export function children(node: Node | Buffer) {
  const body = Buffer.isBuffer(node) ? node : node.body;
  const out: Node[] = [];
  for (let at = 0; at < body.length; at = out[out.length - 1].end) out.push(der(body, at));
  return out;
}
export function oid(node: Node) {
  const b = node.body, parts = [Math.floor(b[0] / 40), b[0] % 40];
  for (let i = 1, value = 0; i < b.length; i++) {
    value = value * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { parts.push(value); value = 0; }
  }
  return parts.join('.');
}
/** UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSS[.f]Z) to ISO. */
function time(node: Node) {
  let s = node.body.toString('latin1');
  if (node.tag === 0x17) s = (Number(s.slice(0, 2)) < 50 ? '20' : '19') + s;
  const date = new Date(`${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}
/** Attribute values keyed by OID from an [0]/[1] IMPLICIT SET OF Attribute. */
function attributes(node?: Node) {
  const out = new Map<string, Node[]>();
  for (const attr of node ? children(node) : []) {
    const [type, values] = children(attr);
    out.set(oid(type), children(values));
  }
  return out;
}
export const certInfo = (c: X509Certificate) => ({ subject: c.subject, issuer: c.issuer, serialNumber: c.serialNumber,
  validFrom: c.validFromDate.toISOString(), validTo: c.validToDate.toISOString(), sha256Fingerprint: c.fingerprint256 });
const normal = (hex: string) => hex.replace(/^(00)+(?=.)/, '').toUpperCase();
/** The certificate a SignerInfo names by issuer and serial (subject-key-identifier signers stay unmatched). */
function signerCertificate(signerInfo: Node, certificates: X509Certificate[]) {
  const sid = children(signerInfo)[1];
  if (sid.tag !== 0x30) return undefined;
  const serial = normal(children(sid)[1].body.toString('hex'));
  return certificates.find(c => normal(c.serialNumber) === serial);
}

/** ContentInfo -> SignedData parts. */
export function signedData(contentInfo: Node) {
  const [type, wrapped] = children(contentInfo);
  if (oid(type) !== SIGNED_DATA || wrapped?.tag !== 0xa0) throw new Error('Expected PKCS#7 SignedData.');
  const parts = children(children(wrapped)[0]);
  const certificates = parts.find(p => p.tag === 0xa0);
  return { encap: parts[2], certificates: certificates ? children(certificates)
    // CertificateChoices also allows tagged attribute or "other" certificates; only plain X.509 is read.
    .filter(c => c.tag === 0x30).map(c => new X509Certificate(c.whole)) : [],
    signer: children(parts[parts.length - 1])[0] };
}

/** Signing time from a legacy countersignature (a SignerInfo) or an RFC 3161 token (a SignedData over TSTInfo). */
function timestamp(unsigned: Map<string, Node[]>) {
  const legacy = unsigned.get(COUNTER_SIGNATURE)?.[0];
  if (legacy) {
    const signed = children(legacy).find(p => p.tag === 0xa0);
    const at = attributes(signed).get(SIGNING_TIME)?.[0];
    return { kind: 'pkcs9-countersignature', time: at ? time(at) : null, authority: null };
  }
  const token = unsigned.get(RFC3161)?.[0];
  if (!token) return null;
  const { encap, certificates, signer } = signedData(token);
  const [type, content] = children(encap);
  let at = null;
  if (oid(type) === TST_INFO) {
    // TSTInfo: version, policy, messageImprint, serialNumber, genTime, ...
    const tst = der(children(content)[0].body, 0);
    at = time(children(tst)[4]);
  }
  const tsa = signerCertificate(signer, certificates);
  return { kind: 'rfc3161', time: at, authority: tsa?.subject ?? null };
}

function readSignature(contentInfo: Node, depth: number, out: object[], wanted: Set<string>, nested: boolean) {
  if (depth > MAX_NESTING) throw new Error('Too many nested signatures.');
  const { encap, certificates, signer } = signedData(contentInfo);
  const [contentType, content] = children(encap);
  if (oid(contentType) !== SPC_INDIRECT_DATA) throw new Error('Signature is not Authenticode SpcIndirectData.');
  // SpcIndirectDataContent: data, DigestInfo { AlgorithmIdentifier, digest OCTET STRING }
  const [algorithm, digest] = children(children(children(content)[0])[1]);
  const algorithmOid = oid(children(algorithm)[0]);
  const digestAlgorithm = OID[algorithmOid] ?? algorithmOid;
  if (OID[algorithmOid]) wanted.add(digestAlgorithm);

  const parts = children(signer);
  const signerCert = signerCertificate(signer, certificates);
  const unsigned = attributes(parts.find(p => p.tag === 0xa1));
  const signingTime = attributes(parts.find(p => p.tag === 0xa0)).get(SIGNING_TIME)?.[0];
  out.push({ nested, digestAlgorithm, fileDigest: digest.body.toString('hex'),
    signer: signerCert ? certInfo(signerCert) : null, claimedSigningTime: signingTime ? time(signingTime) : null,
    timestamp: timestamp(unsigned), certificates: certificates.map(certInfo) });
  for (const inner of unsigned.get(NESTED) ?? []) readSignature(inner, depth + 1, out, wanted, true);
}

export async function inspectAuthenticode(path: string, roots: string[]) {
  const p = await loadPe(path, roots);
  const dir = p.dirs[4];
  const limits = 'Structural parse only. Signatures, certificate chains, revocation and trust are not verified. '
    + 'fileDigestMatches compares the file\'s own Authenticode hash with the digest the signature claims; it does not prove who signed it.';
  if (!dir.size) return { signed: false, limits };
  // The security directory holds a file offset, not an RVA, and sits outside every section.
  if (dir.size > MAX_CERT_TABLE) throw new Error('Refusing an oversized certificate table.');
  const table = await p.fileBytes(dir.rva, dir.size);
  const entries = [], signatures: object[] = [], wanted = new Set<string>();
  for (let at = 0; at + 8 <= table.length;) {
    const length = table.readUInt32LE(at), revision = table.readUInt16LE(at + 4), type = table.readUInt16LE(at + 6);
    if (length < 8 || at + length > table.length) throw new Error('Malformed WIN_CERTIFICATE entry.');
    entries.push({ revision: `0x${revision.toString(16)}`, type: type === 2 ? 'pkcs7' : `0x${type.toString(16)}`, bytes: length });
    if (type === 2) readSignature(der(table.subarray(at + 8, at + length), 0), 0, signatures, wanted, false);
    at += (length + 7) & ~7;
  }
  // Authenticode hashes the whole file except the checksum, the security directory entry and the table itself.
  const checksum = p.pe + 24 + 64;
  const ranges: [number, number][] = [[0, checksum], [checksum + 4, dir.entryOffset], [dir.entryOffset + 8, dir.rva], [dir.rva + dir.size, p.size]];
  const hashes = await digestRanges(path, roots, ranges.filter(([a, b]) => b > a), [...wanted]);
  return { signed: true, entries,
    signatures: signatures.map(s => {
      const sig = s as { digestAlgorithm: string; fileDigest: string };
      return { ...sig, fileDigestMatches: hashes[sig.digestAlgorithm] === undefined ? null : hashes[sig.digestAlgorithm] === sig.fileDigest };
    }), limits };
}
