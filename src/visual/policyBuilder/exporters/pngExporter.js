'use strict';

/**
 * PNG Exporter — Component #41
 *
 * Rasterises a laid-out graph to a PNG binary buffer using only Node.js built-ins
 * (zlib for DEFLATE compression).  No external npm dependencies.
 *
 * Rendering strategy:
 *   - Each node is painted as a filled rectangle with a coloured border.
 *   - Edges are rendered as straight lines using Bresenham's algorithm.
 *   - Text is not rasterised (SVG export should be used for text-bearing output).
 *
 * PNG structure: signature + IHDR + IDAT (zlib-compressed) + IEND.
 */

const zlib = require('zlib');

const { NODE_COLOURS, RISK_COLOURS, RISK_LEVELS, NODE_TYPES } = require('../constants');

// ── Colour helpers ────────────────────────────────────────────────────────────

/**
 * Parse a CSS hex colour ("#rrggbb" or "#rgb") to [r, g, b] uint8 array.
 * Returns [40, 40, 50] for any unrecognised input.
 */
function _parseHex(hex) {
  if (typeof hex !== 'string') return [40, 40, 50];
  const h = hex.replace('#', '');
  if (h.length === 3) {
    return [
      parseInt(h[0] + h[0], 16),
      parseInt(h[1] + h[1], 16),
      parseInt(h[2] + h[2], 16),
    ];
  }
  if (h.length === 6) {
    return [
      parseInt(h.slice(0, 2), 16),
      parseInt(h.slice(2, 4), 16),
      parseInt(h.slice(4, 6), 16),
    ];
  }
  return [40, 40, 50];
}

// Pre-parse common colours used in the palette
const _COLOUR_CACHE = new Map();
function _rgb(hex) {
  if (!_COLOUR_CACHE.has(hex)) _COLOUR_CACHE.set(hex, _parseHex(hex));
  return _COLOUR_CACHE.get(hex);
}

// ── Pixel canvas ──────────────────────────────────────────────────────────────

/**
 * Create an RGBA pixel buffer of dimensions w×h.
 * Initialised to the supplied background colour.
 */
function _createCanvas(w, h, bgHex) {
  const buf = Buffer.alloc(w * h * 3);
  const bg  = _rgb(bgHex || '#0f1117');
  for (let i = 0; i < w * h; i++) {
    buf[i * 3]     = bg[0];
    buf[i * 3 + 1] = bg[1];
    buf[i * 3 + 2] = bg[2];
  }
  return buf;
}

function _setPixel(buf, w, h, px, py, r, g, b) {
  if (px < 0 || py < 0 || px >= w || py >= h) return;
  const idx = (py * w + px) * 3;
  buf[idx]     = r;
  buf[idx + 1] = g;
  buf[idx + 2] = b;
}

/**
 * Fill a rectangle [x,y,x+rw,y+rh) with colour.
 */
function _fillRect(buf, w, h, rx, ry, rw, rh, hex) {
  const [r, g, b] = _rgb(hex);
  const x0 = Math.max(0, rx);
  const y0 = Math.max(0, ry);
  const x1 = Math.min(w, rx + rw);
  const y1 = Math.min(h, ry + rh);
  for (let py = y0; py < y1; py++) {
    for (let px = x0; px < x1; px++) {
      _setPixel(buf, w, h, px, py, r, g, b);
    }
  }
}

/**
 * Draw a rectangle outline (border only).
 */
function _strokeRect(buf, w, h, rx, ry, rw, rh, hex, thickness) {
  const t  = thickness || 1;
  // Top and bottom
  for (let ti = 0; ti < t; ti++) {
    _fillRect(buf, w, h, rx, ry + ti,       rw, 1, hex);
    _fillRect(buf, w, h, rx, ry + rh - 1 - ti, rw, 1, hex);
  }
  // Left and right
  for (let ti = 0; ti < t; ti++) {
    _fillRect(buf, w, h, rx + ti,       ry, 1, rh, hex);
    _fillRect(buf, w, h, rx + rw - 1 - ti, ry, 1, rh, hex);
  }
}

/**
 * Bresenham line algorithm.
 */
function _drawLine(buf, w, h, x0, y0, x1, y1, hex) {
  const [r, g, b] = _rgb(hex);
  let dx  = Math.abs(x1 - x0);
  let dy  = Math.abs(y1 - y0);
  const sx = x0 < x1 ? 1 : -1;
  const sy = y0 < y1 ? 1 : -1;
  let err = dx - dy;

  let cx = x0;
  let cy = y0;

  for (;;) {
    _setPixel(buf, w, h, cx, cy, r, g, b);
    if (cx === x1 && cy === y1) break;
    const e2 = 2 * err;
    if (e2 > -dy) { err -= dy; cx += sx; }
    if (e2 <  dx) { err += dx; cy += sy; }
  }
}

// ── PNG encoding ──────────────────────────────────────────────────────────────

function _uint32BE(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function _crc32(data) {
  // CRC-32 lookup table (IEEE polynomial)
  let c = 0xFFFFFFFF;
  for (let i = 0; i < data.length; i++) {
    c = _CRC_TABLE[(c ^ data[i]) & 0xFF] ^ (c >>> 8);
  }
  return (c ^ 0xFFFFFFFF) >>> 0;
}

// Build CRC32 table lazily
let _CRC_TABLE = null;
function _initCrc() {
  if (_CRC_TABLE) return;
  _CRC_TABLE = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    _CRC_TABLE[n] = c;
  }
}

function _pngChunk(type, data) {
  _initCrc();
  const typeBytes = Buffer.from(type, 'ascii');
  const lenBuf    = _uint32BE(data.length);
  const crcInput  = Buffer.concat([typeBytes, data]);
  const crcBuf    = _uint32BE(_crc32(crcInput));
  return Buffer.concat([lenBuf, typeBytes, data, crcBuf]);
}

function _encodeIHDR(w, h) {
  const b = Buffer.alloc(13);
  b.writeUInt32BE(w, 0);
  b.writeUInt32BE(h, 4);
  b[8]  = 8;  // bit depth
  b[9]  = 2;  // colour type: RGB truecolour
  b[10] = 0;  // compression
  b[11] = 0;  // filter
  b[12] = 0;  // interlace: none
  return _pngChunk('IHDR', b);
}

function _encodeIDAT(pixelBuf, w, h) {
  // Prepend each scanline with filter byte 0 (None)
  const rawRows = Buffer.alloc(h * (1 + w * 3));
  for (let row = 0; row < h; row++) {
    rawRows[row * (1 + w * 3)] = 0; // filter = None
    pixelBuf.copy(rawRows, row * (1 + w * 3) + 1, row * w * 3, (row + 1) * w * 3);
  }
  const compressed = zlib.deflateSync(rawRows, { level: 6 });
  return _pngChunk('IDAT', compressed);
}

function _encodeIEND() {
  return _pngChunk('IEND', Buffer.alloc(0));
}

/**
 * Encode pixel buffer to PNG bytes.
 */
function _encodePng(pixelBuf, w, h) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  return Buffer.concat([
    signature,
    _encodeIHDR(w, h),
    _encodeIDAT(pixelBuf, w, h),
    _encodeIEND(),
  ]);
}

// ── Graph rendering ───────────────────────────────────────────────────────────

function _renderGraphToPixels(layoutGraph, w, h, bgHex) {
  const canvas = _createCanvas(w, h, bgHex);
  const nodes  = layoutGraph.nodes;
  const edges  = Array.isArray(layoutGraph.edges) ? layoutGraph.edges : [];

  // Build node id → node map
  const nodeMap = new Map();
  for (const n of nodes) nodeMap.set(n.id, n);

  // Draw edges first (behind nodes)
  for (const edge of edges) {
    const from = nodeMap.get(edge.from);
    const to   = nodeMap.get(edge.to);
    if (!from || !to) continue;

    const x0 = from.x + Math.floor(from.width  / 2);
    const y0 = from.y + from.height;
    const x1 = to.x   + Math.floor(to.width    / 2);
    const y1 = to.y;

    const edgeColours = {
      contains: '#374151',
      requires: '#15803d',
      produces: '#2563eb',
      inherits: '#7c3aed',
      depends:  '#b45309',
    };
    const stroke = edgeColours[edge.type] || '#374151';
    _drawLine(canvas, w, h, x0, y0, x1, y1, stroke);
  }

  // Draw nodes
  for (const node of nodes) {
    const { x, y, width: nw, height: nh, type, riskLevel } = node;
    if (x === undefined || y === undefined) continue;

    const colours    = NODE_COLOURS[type] || NODE_COLOURS[NODE_TYPES.CONDITION];
    const riskStroke = RISK_COLOURS[riskLevel];
    const borderHex  = riskStroke || colours.stroke;
    const borderW    = riskLevel === RISK_LEVELS.CRITICAL ? 3
                     : riskLevel === RISK_LEVELS.HIGH     ? 2 : 1;

    // Fill
    _fillRect(canvas, w, h, x, y, nw, nh, colours.fill);

    // Border
    _strokeRect(canvas, w, h, x, y, nw, nh, borderHex, borderW);

    // Risk bar at top (4px)
    if (riskStroke) {
      _fillRect(canvas, w, h, x + borderW, y + borderW, nw - borderW * 2, 4, riskStroke);
    }
  }

  return canvas;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Export a laid-out graph to a PNG Buffer.
 *
 * @param {{ nodes: object[], edges: object[], bounds: { width: number, height: number } }} layoutGraph
 * @param {object} [options]
 * @param {string}  [options.background]  — hex background colour (default '#0f1117')
 * @returns {Buffer}  PNG binary data
 */
function exportPng(layoutGraph, options) {
  if (!layoutGraph || typeof layoutGraph !== 'object') {
    throw new TypeError('exportPng: layoutGraph must be a non-null object');
  }
  if (!Array.isArray(layoutGraph.nodes)) {
    throw new TypeError('exportPng: layoutGraph.nodes must be an array');
  }

  const opts   = options || {};
  const bounds = layoutGraph.bounds || { width: 800, height: 600 };
  const w      = Math.max(bounds.width,  64);
  const h      = Math.max(bounds.height, 64);
  const bg     = opts.background || '#0f1117';

  const pixels = _renderGraphToPixels(layoutGraph, w, h, bg);
  return _encodePng(pixels, w, h);
}

module.exports = { exportPng };
