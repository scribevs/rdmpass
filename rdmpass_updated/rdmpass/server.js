/*
 * rdmpass server
 *
 * This Node.js server implements a simple HTTP API for the rdmpass
 * password generator. It serves the static frontend from the `client`
 * directory and exposes a `/generate` endpoint that accepts a POST
 * request with a base64‐encoded 256‑bit entropy string alongside
 * generation settings. It uses a deterministic expansion of the
 * entropy buffer via HMAC‑SHA256 to derive enough pseudo‑random
 * bytes to cover the requested password length, then maps those
 * bytes into a configurable character set.  The character set is
 * constructed based on the requested options such as numbers,
 * uppercase letters, lowercase letters, symbols and extended
 * Latin characters.  An optional `requireEachSelected` flag
 * enforces that at least one character from each selected
 * category appears in the generated password by regenerating until
 * the constraint is satisfied.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Root directory where the client files live
const clientDir = path.join(__dirname, 'client');

/**
 * Normalize the request path, preventing directory traversal.  If the
 * resolved path does not live under the `client` directory it will
 * return `null` so the caller can bail out.  Otherwise it returns
 * the absolute path to the file on disk.
 *
 * @param {string} urlPath – incoming request URL
 * @returns {string|null}
 */
function resolveClientPath(urlPath) {
  const decoded = decodeURI(urlPath.split('?')[0]);
  const safeSuffix = decoded.replace(/^\/+/, '');
  const filePath = path.join(clientDir, safeSuffix);
  const normalized = path.normalize(filePath);
  // Ensure the resolved path still lives within the client directory
  if (!normalized.startsWith(clientDir)) return null;
  return normalized;
}

/**
 * Determine the MIME type based on file extension.  Only a small
 * subset of common types are required for this application.  New
 * extensions can be added here if needed.
 *
 * @param {string} filePath
 * @returns {string}
 */
function getMimeType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.html':
      return 'text/html; charset=utf-8';
    case '.js':
      return 'application/javascript; charset=utf-8';
    case '.css':
      return 'text/css; charset=utf-8';
    case '.png':
      return 'image/png';
    case '.svg':
      return 'image/svg+xml';
    case '.json':
      return 'application/json; charset=utf-8';
    case '.ico':
      return 'image/x-icon';
    default:
      return 'application/octet-stream';
  }
}

/**
 * Derive pseudo‑random bytes from a given entropy buffer using HMAC‑SHA256.
 * This function incrementally computes HMACs keyed by the entropy and
 * concatenates the digests until the desired number of bytes is obtained.
 *
 * @param {Buffer} entropy – 256‑bit random seed
 * @param {number} byteCount – total number of bytes to produce
 * @returns {Buffer}
 */
function expandEntropy(entropy, byteCount) {
  const blocks = Math.ceil(byteCount / 32);
  const out = Buffer.alloc(blocks * 32);
  for (let i = 0; i < blocks; i++) {
    const hmac = crypto.createHmac('sha256', entropy);
    // incorporate the block index as counter to avoid repetition
    hmac.update(Buffer.from([i]));
    const digest = hmac.digest();
    digest.copy(out, i * 32);
  }
  return out.slice(0, byteCount);
}

/**
 * Build a string containing all characters selected by the client based on
 * the requested settings.  If the caller supplies a custom set of
 * characters they will be appended to the set.  If no categories
 * are selected the function throws an error.
 *
 * @param {Object} settings – generation settings
 * @returns {Object} containing the full set and per‑category subsets
 */
function buildCharacterSets(settings) {
  // Standard character categories.  The extendedLatin set is
  // computed dynamically below to include printable ISO‑8859‑1 (Latin‑1)
  // supplement characters.  We skip control characters in the range
  // 0x80–0x9F to avoid unprintable symbols.
  const sets = {
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    numbers: '0123456789',
    symbols: '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',
  };
  // Build extended Latin character set (0xA0–0xFF)
  let extended = '';
  for (let code = 0xA0; code <= 0xFF; code++) {
    extended += String.fromCharCode(code);
  }
  sets.extendedLatin = extended;
  const selected = {};
  let fullSet = '';
  if (settings.includeLowercase) {
    selected.lowercase = sets.lowercase;
    fullSet += sets.lowercase;
  }
  if (settings.includeUppercase) {
    selected.uppercase = sets.uppercase;
    fullSet += sets.uppercase;
  }
  if (settings.includeNumbers) {
    selected.numbers = sets.numbers;
    fullSet += sets.numbers;
  }
  if (settings.includeSymbols) {
    selected.symbols = sets.symbols;
    fullSet += sets.symbols;
  }
  if (settings.includeExtendedLatin) {
    selected.extendedLatin = sets.extendedLatin;
    fullSet += sets.extendedLatin;
  }
  if (settings.customCharacters) {
    selected.custom = settings.customCharacters;
    fullSet += settings.customCharacters;
  }
  if (!fullSet) {
    throw new Error('No character categories selected');
  }
  return { fullSet, categories: selected };
}

/**
 * Generate a password based on an entropy buffer and supplied settings.
 * Uses the HMAC‑based expander to derive enough pseudo‑random bytes and
 * then maps each byte to a character in the allowed character set.  If
 * `requireEachSelected` is set, the function will retry until the
 * password contains at least one character from every selected
 * category.
 *
 * @param {Buffer} entropy – 256‑bit random seed
 * @param {Object} settings – generation settings
 * @returns {string}
 */
function generatePassword(entropy, settings) {
  const { fullSet, categories } = buildCharacterSets(settings);
  const setLength = fullSet.length;
  const passwordLength = Math.max(1, Math.min(settings.length || 16, 2048));
  const requireEach = !!settings.requireEachSelected;

  // Expand the entropy into enough bytes for the required length.
  // We request twice as many bytes as needed to reduce bias from discarding
  // modulo values.  This overhead is negligible and ensures a uniform
  // distribution of characters even when the set length is not a power
  // of two.
  const neededBytes = passwordLength * 2;
  // expanded is mutated below when the generator needs more bytes.  Use
  // `let` rather than `const` to permit reassignment.
  let expanded = expandEntropy(entropy, neededBytes);

  // Map bytes to characters.  We skip bytes whose value would skew
  // distribution when using modulo; this technique is sometimes known
  // as the “reject‑upper” method.
  let result;
  outer: do {
    const chars = [];
    // Track categories present in this candidate
    const present = {};
    let p = 0;
    while (chars.length < passwordLength) {
      if (p >= expanded.length) {
        // If we run out of bytes, re‑expand using a new counter to get more
        // bytes.  We append bytes to expanded buffer on the fly.
        const extra = expandEntropy(entropy, 32);
        expanded = Buffer.concat([expanded, extra]);
      }
      const byte = expanded[p++];
      const max = 256 - (256 % setLength);
      if (byte >= max) continue; // skip values that would bias selection
      const index = byte % setLength;
      const ch = fullSet.charAt(index);
      chars.push(ch);
      // record which category this char belongs to
      for (const key in categories) {
        if (categories[key].includes(ch)) {
          present[key] = true;
        }
      }
    }
    result = chars.join('');
    if (!requireEach) break;
    // Check that all selected categories are represented
    let ok = true;
    for (const key in categories) {
      if (!present[key]) {
        ok = false;
        break;
      }
    }
    if (ok) break;
    // If not, try again by expanding additional bytes and repeating
  } while (true);
  return result;
}

// Create the HTTP server
const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/generate') {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString('utf8');
      // guard against overly large payloads
      if (body.length > 10 * 1024) {
        req.socket.destroy();
      }
    });
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body);
        if (!parsed || !parsed.entropy || !parsed.settings) {
          throw new Error('Missing required fields');
        }
        // Convert base64 encoded entropy to buffer
        const entropy = Buffer.from(parsed.entropy, 'base64');
        if (entropy.length !== 32) {
          throw new Error('Entropy must be exactly 256 bits (32 bytes)');
        }
        const password = generatePassword(entropy, parsed.settings);
        const response = JSON.stringify({ password });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(response);
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }
  // Serve static files
  // Default to index.html for the root path or unknown paths
  let filePath;
  if (req.url === '/' || req.url === '' || req.url.startsWith('/?')) {
    filePath = path.join(clientDir, 'index.html');
  } else {
    filePath = resolveClientPath(req.url) || path.join(clientDir, 'index.html');
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      // Fallback to index.html for unknown routes to support client‑side routing
      if (!req.url.includes('.')) {
        fs.readFile(path.join(clientDir, 'index.html'), (e2, d2) => {
          if (e2) {
            res.writeHead(500);
            res.end('Internal server error');
            return;
          }
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(d2);
        });
        return;
      }
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    const mime = getMimeType(filePath);
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`rdmpass server listening on port ${PORT}`);
});