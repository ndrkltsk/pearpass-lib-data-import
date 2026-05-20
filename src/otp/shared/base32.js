const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/**
 * Encodes a byte array to a base32 string (RFC 4648, no padding).
 * @param {Uint8Array | Buffer} bytes
 * @returns {string}
 */
export function encodeBase32(bytes) {
  let result = ''
  let bits = 0
  let accumulator = 0

  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      result += ALPHABET[(accumulator >>> bits) & 0x1f]
    }
  }

  if (bits > 0) {
    result += ALPHABET[(accumulator << (5 - bits)) & 0x1f]
  }

  return result
}
