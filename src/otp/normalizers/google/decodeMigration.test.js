import { decodeMigrationUri } from './decodeMigration'
import { encodeMigrationPayload, makeGoogleUri } from './testHelpers'

const HELLO_BYTES = [0x48, 0x65, 0x6c, 0x6c, 0x6f] // "Hello"

function makeUri(opts) {
  return makeGoogleUri(encodeMigrationPayload(opts))
}

describe('decodeMigrationUri', () => {
  describe('valid URIs', () => {
    it('decodes a single TOTP entry', () => {
      const uri = makeUri({
        otpParams: [
          {
            secret: HELLO_BYTES,
            name: 'alice@example.com',
            issuer: 'Example',
            type: 2
          }
        ]
      })
      const result = decodeMigrationUri(uri)

      expect(result.otpParameters).toHaveLength(1)
      const params = result.otpParameters[0]
      expect(params.name).toBe('alice@example.com')
      expect(params.issuer).toBe('Example')
      expect(Array.from(params.secret)).toEqual(HELLO_BYTES)
      expect(params.type).toBe(2)
    })

    it('decodes multiple entries in one payload', () => {
      const uri = makeUri({
        otpParams: [
          { secret: HELLO_BYTES, name: 'alice', issuer: 'ServiceA', type: 2 },
          {
            secret: [0x01, 0x02, 0x03],
            name: 'bob',
            issuer: 'ServiceB',
            type: 2
          }
        ]
      })
      const result = decodeMigrationUri(uri)
      expect(result.otpParameters).toHaveLength(2)
      expect(result.otpParameters[0].name).toBe('alice')
      expect(result.otpParameters[1].name).toBe('bob')
    })

    it('decodes HOTP entry with counter', () => {
      const uri = makeUri({
        otpParams: [
          { secret: HELLO_BYTES, name: 'hotp-user', type: 1, counter: 42 }
        ]
      })
      const result = decodeMigrationUri(uri)
      const params = result.otpParameters[0]
      expect(params.type).toBe(1)
      expect(params.counter).toBe(42)
    })

    it('reads batch metadata correctly', () => {
      const uri = makeUri({
        otpParams: [{ secret: HELLO_BYTES, name: 'test' }],
        version: 1,
        batchSize: 3,
        batchIndex: 1,
        batchId: 99
      })
      const result = decodeMigrationUri(uri)
      expect(result.version).toBe(1)
      expect(result.batchSize).toBe(3)
      expect(result.batchIndex).toBe(1)
      expect(result.batchId).toBe(99)
    })
  })

  describe('errors', () => {
    it('throws on wrong protocol', () => {
      expect(() =>
        decodeMigrationUri('otpauth://totp/test?secret=ABC')
      ).toThrow('must start with otpauth-migration://')
    })

    it('throws on non-string input', () => {
      expect(() => decodeMigrationUri(42)).toThrow(
        'must start with otpauth-migration://'
      )
    })

    it('throws when data parameter is missing', () => {
      expect(() => decodeMigrationUri('otpauth-migration://offline')).toThrow(
        'missing "data" query parameter'
      )
    })

    it('throws on empty data parameter', () => {
      expect(() =>
        decodeMigrationUri('otpauth-migration://offline?data=')
      ).toThrow()
    })
  })
})
