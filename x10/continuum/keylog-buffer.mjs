// Research fixture NSS keylog ingestion. Never stringify random/secret bytes.
// The caller owns the two decoded buffers on success and must wipe them when
// not retained, and eventually wipe retained values. This cannot wipe earlier
// copies inside Node/OpenSSL, compiler temporaries or the whole process.
const invalid = () => {
  const error = new Error('keylog_invalid');
  error.code = 'keylog_invalid';
  return error;
};
const requireValue = condition => { if (!condition) throw invalid(); };
const nibble = value => value >= 48 && value <= 57 ? value - 48
  : value >= 65 && value <= 70 ? value - 55
    : value >= 97 && value <= 102 ? value - 87 : -1;

/** Consume one complete NSS line, with an optional single final LF.
 * Only a public label becomes a string. Exact ASCII separators/field sizes
 * are required even for unknown labels; CRLF, padding and ignored tails are
 * not normalized. The original Buffer is cleared on every return/throw. */
export function parseKeylogBuffer(line) {
  let random, secret;
  try {
    requireValue(Buffer.isBuffer(line) && line.length > 0 && line.length <= 512);
    const end = line[line.length - 1] === 10 ? line.length - 1 : line.length;
    const a = line.indexOf(32), b = line.indexOf(32, a + 1);
    requireValue(a >= 1 && a <= 64 && b === a + 65 && end === b + 65);
    for (let i = 0; i < a; i++) {
      const c = line[i];
      requireValue((c >= 65 && c <= 90) || (c >= 48 && c <= 57) || c === 95);
    }
    random = Buffer.alloc(32); secret = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
      const rh = nibble(line[a + 1 + i * 2]), rl = nibble(line[a + 2 + i * 2]);
      const sh = nibble(line[b + 1 + i * 2]), sl = nibble(line[b + 2 + i * 2]);
      requireValue(rh >= 0 && rl >= 0 && sh >= 0 && sl >= 0);
      random[i] = rh * 16 + rl; secret[i] = sh * 16 + sl;
    }
    return { label: line.subarray(0, a).toString('ascii'), random, secret };
  } catch (error) {
    random?.fill(0); secret?.fill(0);
    throw invalid();
  } finally {
    if (Buffer.isBuffer(line)) line.fill(0);
  }
}
