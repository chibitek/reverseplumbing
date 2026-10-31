// Minimal property-list reader for application metadata. Top-level dictionary
// only: nested containers are reported by type rather than expanded, because
// nothing we read out of an Info.plist or an entitlements blob needs them.
// Both formats are here because 19% of installed macOS apps ship a binary
// Info.plist and the rest ship XML.

export type PlistValue = string | number | boolean | { type: 'dict' | 'array' | 'data'; bytes?: number };
export type PlistDict = Record<string, PlistValue>;

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

function decodeEntities(text: string) {
  return text.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-z]+);/g, (whole, body: string) => {
    if (body[0] !== '#') return ENTITIES[body] ?? whole;
    const point = body[1] === 'x' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
    return point >= 0 && point <= 0x10ffff ? String.fromCodePoint(point) : whole;
  });
}

function parseXmlPlist(text: string): PlistDict {
  const out: PlistDict = {};
  const tag = /<(\/?)(key|string|integer|real|true|false|data|date|dict|array)\s*(\/?)>/g;
  let depth = 0;
  let key: string | null = null;
  let match: RegExpExecArray | null;

  // Consumes the character data up to `close` and leaves the cursor past it.
  const textUntil = (close: string) => {
    const end = text.indexOf(close, tag.lastIndex);
    if (end < 0) throw new Error('Unterminated plist element.');
    const raw = text.slice(tag.lastIndex, end);
    tag.lastIndex = end + close.length;
    return raw;
  };

  while ((match = tag.exec(text))) {
    const [, closing, name, selfClosing] = match;
    if (name === 'dict' || name === 'array') {
      if (closing) { depth--; continue; }
      // An empty `<dict/>` or `<array/>` is a whole value, not a new level.
      if (selfClosing) {
        if (depth === 1 && key !== null) { out[key] = { type: name }; key = null; }
        continue;
      }
      depth++;
      // A container opening below the root is this key's value; record its
      // shape and let the rest of the walk skip over its contents.
      if (depth > 1 && key !== null) { out[key] = { type: name }; key = null; }
      continue;
    }
    if (depth !== 1) continue;
    if (name === 'key') { key = decodeEntities(textUntil('</key>')); continue; }
    if (key === null) continue;
    if (name === 'true' || name === 'false') { if (selfClosing) { out[key] = name === 'true'; key = null; } continue; }
    if (name === 'string') out[key] = decodeEntities(textUntil('</string>'));
    else if (name === 'integer' || name === 'real') out[key] = Number(textUntil(`</${name}>`).trim());
    else if (name === 'date') out[key] = textUntil('</date>').trim();
    else out[key] = { type: 'data', bytes: Math.floor(textUntil('</data>').replace(/\s+/g, '').length * 3 / 4) };
    key = null;
  }
  if (depth !== 0) throw new Error('Unbalanced plist containers.');
  return out;
}

function parseBinaryPlist(bytes: Buffer): PlistDict {
  if (bytes.length < 40) throw new Error('Truncated binary plist.');
  const trailer = bytes.length - 32;
  const offsetSize = bytes.readUInt8(trailer + 6);
  const refSize = bytes.readUInt8(trailer + 7);
  const objectCount = Number(bytes.readBigUInt64BE(trailer + 8));
  const rootIndex = Number(bytes.readBigUInt64BE(trailer + 16));
  const tableStart = Number(bytes.readBigUInt64BE(trailer + 24));
  if (offsetSize < 1 || offsetSize > 6 || refSize < 1 || refSize > 6) throw new Error('Unsupported binary plist integer widths.');
  if (objectCount < 1 || objectCount > 100_000 || rootIndex >= objectCount) throw new Error('Invalid binary plist object count.');
  if (tableStart + objectCount * offsetSize > trailer) throw new Error('Invalid binary plist offset table.');

  const offsetAt = (index: number) => {
    if (index >= objectCount) throw new Error('Binary plist reference out of range.');
    return bytes.readUIntBE(tableStart + index * offsetSize, offsetSize);
  };
  // Collection and data markers carry their count inline, or in a trailing
  // integer object when the low nibble is 0xf.
  const lengthAt = (start: number, info: number) => {
    if (info !== 0xf) return { length: info, next: start + 1 };
    const marker = bytes.readUInt8(start + 1);
    if ((marker & 0xf0) !== 0x10) throw new Error('Invalid binary plist length marker.');
    const width = 1 << (marker & 0x0f);
    if (width > 6) throw new Error('Unsupported binary plist length width.');
    return { length: bytes.readUIntBE(start + 2, width), next: start + 2 + width };
  };

  const readObject = (index: number): PlistValue => {
    const start = offsetAt(index);
    const marker = bytes.readUInt8(start);
    const type = marker >> 4;
    const info = marker & 0x0f;
    if (type === 0) return info === 9 ? true : info === 8 ? false : '';
    if (type === 1) {
      const width = 1 << info;
      return width <= 6 ? bytes.readUIntBE(start + 1, width) : Number(bytes.readBigInt64BE(start + 1));
    }
    if (type === 2) return (1 << info) === 4 ? bytes.readFloatBE(start + 1) : bytes.readDoubleBE(start + 1);
    if (type === 3) return new Date(Date.UTC(2001, 0, 1) + bytes.readDoubleBE(start + 1) * 1000).toISOString();
    if (type === 4) return { type: 'data', bytes: lengthAt(start, info).length };
    if (type === 5) { const { length, next } = lengthAt(start, info); return bytes.toString('latin1', next, next + length); }
    if (type === 6) {
      const { length, next } = lengthAt(start, info);
      return Buffer.from(bytes.subarray(next, next + length * 2)).swap16().toString('utf16le');
    }
    if (type === 8) return bytes.readUIntBE(start + 1, info + 1);
    if (type === 10 || type === 12) return { type: 'array' };
    if (type === 13) return { type: 'dict' };
    throw new Error('Unsupported binary plist object type.');
  };

  const start = offsetAt(rootIndex);
  const marker = bytes.readUInt8(start);
  if (marker >> 4 !== 0x0d) throw new Error('Expected a dictionary at the binary plist root.');
  const { length, next } = lengthAt(start, marker & 0x0f);
  const out: PlistDict = {};
  for (let i = 0; i < length; i++) {
    const key = readObject(bytes.readUIntBE(next + i * refSize, refSize));
    if (typeof key !== 'string') continue;
    out[key] = readObject(bytes.readUIntBE(next + (length + i) * refSize, refSize));
  }
  return out;
}

export function parsePlist(bytes: Buffer): PlistDict {
  if (bytes.subarray(0, 8).toString('latin1') === 'bplist00') return parseBinaryPlist(bytes);
  const text = bytes.toString('utf8');
  if (!text.includes('<plist')) throw new Error('Expected an XML or binary property list.');
  return parseXmlPlist(text);
}

/** Read a plist value as a string only when it really is one. */
export function plistString(dict: PlistDict, key: string): string | null {
  const value = dict[key];
  return typeof value === 'string' ? value : null;
}
