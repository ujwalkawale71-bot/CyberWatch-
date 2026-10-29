const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

// CRC32 implementation for standard PNG chunks
function createCrcTable() {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      if (c & 1) {
        c = 0xedb88320 ^ (c >>> 1);
      } else {
        c = c >>> 1;
      }
    }
    table[n] = c;
  }
  return table;
}

const crcTable = createCrcTable();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function makeChunk(type, data) {
  const len = data.length;
  const buf = Buffer.alloc(8 + len + 4);
  buf.writeUInt32BE(len, 0);
  buf.write(type, 4, 4, 'ascii');
  data.copy(buf, 8);
  const typeAndData = buf.subarray(4, 8 + len);
  const crc = crc32(typeAndData);
  buf.writeUInt32BE(crc, 8 + len);
  return buf;
}

function generatePng(width, height, pixelFn) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8; // 8-bit depth
  ihdrData[9] = 6; // RGBA color
  ihdrData[10] = 0; // compression
  ihdrData[11] = 0; // filter
  ihdrData[12] = 0; // interlace
  const ihdrChunk = makeChunk('IHDR', ihdrData);

  // Scanlines with filter byte 0
  const rawData = Buffer.alloc(height * (1 + width * 4));
  let offset = 0;

  for (let y = 0; y < height; y++) {
    rawData[offset++] = 0; // Filter None
    for (let x = 0; x < width; x++) {
      const [r, g, b, a] = pixelFn(x, y, width, height);
      rawData[offset++] = r;
      rawData[offset++] = g;
      rawData[offset++] = b;
      rawData[offset++] = a;
    }
  }

  const compressed = zlib.deflateSync(rawData);
  const idatChunk = makeChunk('IDAT', compressed);
  const iendChunk = makeChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

// Function to render the CyberWatch Shield & Scan Graphic
function renderCyberWatchPixel(x, y, size) {
  // Normalize to -1.0 to 1.0 coordinate system
  const nx = (x + 0.5) / (size / 2) - 1.0; // -1 to 1
  const ny = (y + 0.5) / (size / 2) - 1.0; // -1 to 1

  // Outer Shield Profile equation
  // Top horizontal with slight dip, vertical upper sides, tapered lower point
  const topY = -0.85;
  const midY = 0.05;
  const bottomY = 0.90;
  const sideX = 0.78;

  let inShield = false;
  let distToEdge = 999;

  if (ny >= topY && ny <= bottomY) {
    let boundX = 0;
    if (ny < midY) {
      // Upper curve/slight bulge
      const t = (ny - topY) / (midY - topY);
      boundX = sideX * (0.92 + 0.08 * Math.sin(t * Math.PI * 0.5));
    } else {
      // Lower taper to bottom tip
      const t = (ny - midY) / (bottomY - midY);
      // Quadratic curve tapering down to 0
      boundX = sideX * Math.pow(1 - t, 0.75);
    }

    if (Math.abs(nx) <= boundX) {
      inShield = true;
      distToEdge = boundX - Math.abs(nx);
    }
  }

  // Transparent outside
  if (!inShield) {
    // Subtle outer glow/halo for anti-aliasing
    if (distToEdge < 0.08 && ny >= topY - 0.05 && ny <= bottomY + 0.05) {
      return [6, 182, 212, Math.floor(Math.max(0, (0.08 - distToEdge) * 100))];
    }
    return [0, 0, 0, 0];
  }

  // Border thickness proportional to size
  const borderWidth = size <= 16 ? 0.22 : size <= 32 ? 0.16 : 0.12;
  const isBorder = distToEdge < borderWidth;

  // Outer Border: Cyan to Electric Blue gradient
  if (isBorder) {
    const borderGrad = (ny + 1) / 2;
    const r = Math.floor(6 + borderGrad * 30);
    const g = Math.floor(182 - borderGrad * 50);
    const b = Math.floor(212 + borderGrad * 40);
    return [r, g, b, 255];
  }

  // Inside shield body: Dark Slate/Navy Cyber aesthetic
  // (#0b1329 down to #1e1b4b)
  const depthGrad = (ny + 0.85) / 1.75;
  let r = Math.floor(11 + depthGrad * 18);
  let g = Math.floor(19 + depthGrad * 15);
  let b = Math.floor(41 + depthGrad * 35);
  let a = 255;

  // Radar / Scan Sweep effect across the middle
  // Horizontal beam near y = -0.1 to 0.2
  const beamCenter = -0.05;
  const distToBeam = Math.abs(ny - beamCenter);
  if (distToBeam < 0.18) {
    const intensity = Math.pow(1 - distToBeam / 0.18, 2);
    // Cyan beam glow (#06b6d4)
    r = Math.min(255, r + Math.floor(intensity * 10));
    g = Math.min(255, g + Math.floor(intensity * 160));
    b = Math.min(255, b + Math.floor(intensity * 210));
  }

  // Radar Arc Ring
  const distFromCenter = Math.sqrt(nx * nx + (ny + 0.05) * (ny + 0.05));
  if (Math.abs(distFromCenter - 0.42) < 0.06) {
    const ringIntensity = 1 - Math.abs(distFromCenter - 0.42) / 0.06;
    r = Math.min(255, r + Math.floor(ringIntensity * 30));
    g = Math.min(255, g + Math.floor(ringIntensity * 190));
    b = Math.min(255, b + Math.floor(ringIntensity * 230));
  }

  // Center Shield Emblem: Checkmark / Eye Reticle
  // Draw an inverted crest / shield check mark
  const inCenterReticle =
    (Math.abs(nx) < 0.08 && Math.abs(ny - 0.05) < 0.28) || // vertical cross
    (Math.abs(ny + 0.05) < 0.08 && Math.abs(nx) < 0.28); // horizontal cross

  if (inCenterReticle && size >= 32) {
    r = 56;
    g = 189;
    b = 248; // sky-400
  }

  // Inner core glow dot
  if (distFromCenter < 0.12) {
    r = 255;
    g = 255;
    b = 255;
  }

  return [r, g, b, a];
}

const targetDir = path.resolve(__dirname, 'assets');
if (!fs.existsSync(targetDir)) {
  fs.mkdirSync(targetDir, { recursive: true });
}

const sizes = [16, 32, 48, 128];
sizes.forEach((s) => {
  const png = generatePng(s, s, (x, y, w) => renderCyberWatchPixel(x, y, w));
  const filename = path.join(targetDir, `icon${s}.png`);
  fs.writeFileSync(filename, png);
  console.log(`Generated ${filename} (${png.length} bytes)`);
});
