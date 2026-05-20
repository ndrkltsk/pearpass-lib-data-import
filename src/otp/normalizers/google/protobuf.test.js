import { decodeMigrationPayload } from './protobuf.js'
import { encodeMigrationPayload } from './testHelpers.js'

const SECRET = [0x48, 0x65, 0x6c, 0x6c, 0x6f] // "Hello"

describe('decodeMigrationPayload', () => {
  describe('payload metadata', () => {
    it('decodes version, batchSize, batchIndex, batchId', () => {
      const buf = encodeMigrationPayload({
        otpParams: [{ secret: SECRET }],
        version: 2,
        batchSize: 3,
        batchIndex: 1,
        batchId: 42
      })
      const result = decodeMigrationPayload(buf)
      expect(result.version).toBe(2)
      expect(result.batchSize).toBe(3)
      expect(result.batchIndex).toBe(1)
      expect(result.batchId).toBe(42)
    })

    it('defaults version=0 and batchId=0 when not encoded', () => {
      // Encode only the otp entry field (field 1) with no metadata fields
      const paramBuf = encodeMigrationPayload({ otpParams: [{ secret: SECRET }], version: 0, batchSize: 1, batchIndex: 0, batchId: 0 })
      const result = decodeMigrationPayload(paramBuf)
      expect(result.version).toBe(0)
      expect(result.batchId).toBe(0)
    })
  })

  describe('otpParameters', () => {
    it('returns an array with one entry for a single otp param', () => {
      const buf = encodeMigrationPayload({ otpParams: [{ secret: SECRET }] })
      const { otpParameters } = decodeMigrationPayload(buf)
      expect(otpParameters).toHaveLength(1)
    })

    it('returns multiple entries when multiple otp params are encoded', () => {
      const buf = encodeMigrationPayload({
        otpParams: [
          { secret: SECRET, name: 'alice' },
          { secret: SECRET, name: 'bob' }
        ]
      })
      const { otpParameters } = decodeMigrationPayload(buf)
      expect(otpParameters).toHaveLength(2)
      expect(otpParameters[0].name).toBe('alice')
      expect(otpParameters[1].name).toBe('bob')
    })

    it('decodes secret as Uint8Array with correct bytes', () => {
      const buf = encodeMigrationPayload({ otpParams: [{ secret: SECRET }] })
      const { secret } = decodeMigrationPayload(buf).otpParameters[0]
      expect(secret).toBeInstanceOf(Uint8Array)
      expect(Array.from(secret)).toEqual(SECRET)
    })

    it('decodes name and issuer strings', () => {
      const buf = encodeMigrationPayload({
        otpParams: [{ secret: SECRET, name: 'alice@example.com', issuer: 'GitHub' }]
      })
      const { name, issuer } = decodeMigrationPayload(buf).otpParameters[0]
      expect(name).toBe('alice@example.com')
      expect(issuer).toBe('GitHub')
    })

    it('decodes algorithm field', () => {
      const buf = encodeMigrationPayload({ otpParams: [{ secret: SECRET, algorithm: 3 }] }) // SHA512
      const { algorithm } = decodeMigrationPayload(buf).otpParameters[0]
      expect(algorithm).toBe(3)
    })

    it('decodes digits field', () => {
      const buf = encodeMigrationPayload({ otpParams: [{ secret: SECRET, digits: 2 }] }) // EIGHT
      const { digits } = decodeMigrationPayload(buf).otpParameters[0]
      expect(digits).toBe(2)
    })

    it('decodes type field', () => {
      const buf = encodeMigrationPayload({ otpParams: [{ secret: SECRET, type: 2 }] }) // TOTP
      const { type } = decodeMigrationPayload(buf).otpParameters[0]
      expect(type).toBe(2)
    })

    it('decodes counter for HOTP entries', () => {
      const buf = encodeMigrationPayload({ otpParams: [{ secret: SECRET, type: 1, counter: 7 }] })
      const { counter, type } = decodeMigrationPayload(buf).otpParameters[0]
      expect(type).toBe(1)
      expect(counter).toBe(7)
    })

    it('defaults counter to 0 when not encoded', () => {
      const buf = encodeMigrationPayload({ otpParams: [{ secret: SECRET, type: 2 }] })
      const { counter } = decodeMigrationPayload(buf).otpParameters[0]
      expect(counter).toBe(0)
    })

    it('decodes empty name and missing issuer gracefully', () => {
      const buf = encodeMigrationPayload({ otpParams: [{ secret: SECRET, name: '' }] })
      const { name, issuer } = decodeMigrationPayload(buf).otpParameters[0]
      expect(name).toBe('')
      expect(issuer).toBe('')
    })
  })

  describe('returns empty otpParameters for empty payload', () => {
    it('returns empty array when no otp params are present', () => {
      const buf = encodeMigrationPayload({ otpParams: [] })
      const { otpParameters } = decodeMigrationPayload(buf)
      expect(otpParameters).toEqual([])
    })
  })

  describe('accepts Buffer and Uint8Array', () => {
    it('accepts a Node.js Buffer', () => {
      const buf = encodeMigrationPayload({ otpParams: [{ secret: SECRET }] })
      expect(() => decodeMigrationPayload(buf)).not.toThrow()
    })

    it('accepts a Uint8Array', () => {
      const buf = encodeMigrationPayload({ otpParams: [{ secret: SECRET }] })
      const u8 = new Uint8Array(buf)
      expect(() => decodeMigrationPayload(u8)).not.toThrow()
    })
  })
})
