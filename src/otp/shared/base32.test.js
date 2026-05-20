import { encodeBase32 } from './base32'

describe('encodeBase32', () => {
  it('encodes a known byte sequence correctly', () => {
    // "Hello" in ASCII = [0x48, 0x65, 0x6c, 0x6c, 0x6f] → JBSWY3DP
    expect(encodeBase32(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]))).toBe(
      'JBSWY3DP'
    )
  })

  it('encodes a single byte', () => {
    // 0x00 → first 5 bits are 0 → 'A', remaining 3 bits padded to → 'A'
    expect(encodeBase32(new Uint8Array([0x00]))).toBe('AA')
  })

  it('encodes an empty array to an empty string', () => {
    expect(encodeBase32(new Uint8Array([]))).toBe('')
  })

  it('uses only uppercase RFC 4648 base32 alphabet characters', () => {
    const result = encodeBase32(new Uint8Array([0xff, 0xee, 0xdd, 0xcc]))
    expect(result).toMatch(/^[A-Z2-7]+$/)
  })

  it('encodes a multi-byte sequence without padding characters', () => {
    // No '=' padding should appear — the function omits padding
    const result = encodeBase32(new Uint8Array([0x01, 0x02, 0x03]))
    expect(result).not.toContain('=')
  })

  it('accepts a Buffer', () => {
    const buf = Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f])
    expect(encodeBase32(buf)).toBe('JBSWY3DP')
  })
})
