import { normalizeImport } from './normalizeImport'
import {
  encodeMigrationPayload,
  makeGoogleUri
} from '../normalizers/google/testHelpers'

// "Hello" in ASCII = JBSWY3DP in base32
const HELLO_BYTES = [0x48, 0x65, 0x6c, 0x6c, 0x6f]

function makeSingleGoogleUri(overrides = {}) {
  return makeGoogleUri(
    encodeMigrationPayload({
      otpParams: [
        {
          secret: HELLO_BYTES,
          name: 'alice@example.com',
          issuer: 'Example',
          type: 2
        }
      ],
      batchSize: 1,
      batchIndex: 0,
      batchId: 1,
      ...overrides
    })
  )
}

describe('normalizeImport — Google Authenticator migration', () => {
  it('decodes and normalises a single QR code', () => {
    const result = normalizeImport(makeSingleGoogleUri())

    expect(result.status).toBe('complete')
    expect(result.records).toHaveLength(1)
    expect(result.records[0]).toMatchObject({
      type: 'TOTP',
      label: 'alice@example.com',
      issuer: 'Example',
      secret: 'JBSWY3DP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30
    })
  })

  it('accepts an array with a single migration URI', () => {
    const result = normalizeImport([makeSingleGoogleUri()])
    expect(result.status).toBe('complete')
  })

  it('assembles a complete two-QR batch', () => {
    const uri0 = makeGoogleUri(
      encodeMigrationPayload({
        otpParams: [{ secret: HELLO_BYTES, name: 'alice', type: 2 }],
        batchSize: 2,
        batchIndex: 0,
        batchId: 42
      })
    )
    const uri1 = makeGoogleUri(
      encodeMigrationPayload({
        otpParams: [{ secret: [0x01, 0x02, 0x03], name: 'bob', type: 2 }],
        batchSize: 2,
        batchIndex: 1,
        batchId: 42
      })
    )

    const result = normalizeImport([uri0, uri1])
    expect(result.status).toBe('complete')
    expect(result.records).toHaveLength(2)
    expect(result.records[0].label).toBe('alice')
    expect(result.records[1].label).toBe('bob')
  })

  it('returns incomplete-batch when parts are missing', () => {
    const uri = makeGoogleUri(
      encodeMigrationPayload({
        otpParams: [{ secret: HELLO_BYTES, name: 'alice', type: 2 }],
        batchSize: 2,
        batchIndex: 0,
        batchId: 99
      })
    )

    const result = normalizeImport([uri])
    expect(result.status).toBe('incomplete-batch')
    expect(result.expected).toBe(2)
    expect(result.received).toBe(1)
    expect(result.batchId).toBe(99)
  })
})

describe('normalizeImport — real-world Google Authenticator export', () => {
  // Single-batch QR (batchSize=1, batchIndex=0) containing 10 real accounts
  const REAL_URI =
    'otpauth-migration://offline?data=CiQKCkhlbGxvId6tvu8SBkdpb3JnaRoIZmFjZWJvb2sgASgBMAIKMQoKSGVsbG8h3q2%2B7xITZ2lvcmdpa2hhdEBtYWlsLmNvbRoITGlua2VkaW4gASgBMAIKKAoKTmVsbG8gHq2%2B7xINa2hhdEBtYWlsLmNvbRoFR21haWwgASgBMAIKKQoKTmVsbG8gHq2%2B9xINa2hhdEBtYWlsLmNvbRoGR29vbGdlIAEoATACCh4KCkhlnGxvEd6tvu8SBFRlc3QaBGVCYXkgASgBMAIKIQoKSGWcbG8R3q2%2B6xIEVGVzdBoHRHJvcGJveCABKAEwAgoeCgpIZZxsbxHevb7rEgZUZXN0MjMaAkVBIAEoATACCigKCkhlnGxvEd69vu4SBlRlc3QyMxoMRGlnaXRhbE9jZWFuIAEoATACCiIKCkhlnGxvcd69vu4SBlRlc3QyMxoGR2l0SHViIAEoATACCiIKCkhlnGxvcd7dvu4SBlRlc3QyMxoGSGVyb2t1IAEoATACEAIYASAA'

  it('decodes all 10 accounts', () => {
    const result = normalizeImport(REAL_URI)
    expect(result.status).toBe('complete')
    expect(result.records).toHaveLength(10)
  })

  it('every record has required fields with correct types', () => {
    const { records } = normalizeImport(REAL_URI)
    for (const record of records) {
      expect(record.type).toBe('TOTP')
      expect(record.algorithm).toBe('SHA1')
      expect(record.digits).toBe(6)
      expect(record.period).toBe(30)
      expect(typeof record.secret).toBe('string')
      expect(record.secret.length).toBeGreaterThan(0)
      expect(typeof record.label).toBe('string')
    }
  })

  it('decodes records in the correct order with expected issuers', () => {
    const { records } = normalizeImport(REAL_URI)
    const issuers = records.map((r) => r.issuer)
    expect(issuers).toEqual([
      'facebook',
      'Linkedin',
      'Gmail',
      'Goolge',
      'eBay',
      'Dropbox',
      'EA',
      'DigitalOcean',
      'GitHub',
      'Heroku'
    ])
  })

  it('decodes labels correctly', () => {
    const { records } = normalizeImport(REAL_URI)
    expect(records[0].label).toBe('Giorgi')
    expect(records[1].label).toBe('giorgikhat@mail.com')
    expect(records[2].label).toBe('khat@mail.com')
    expect(records[4].label).toBe('Test')
    expect(records[6].label).toBe('Test23')
  })

  it('decodes secrets as non-empty base32 strings', () => {
    const { records } = normalizeImport(REAL_URI)
    expect(records[0].secret).toBe('JBSWY3DPEHPK3PXP')
    expect(records[1].secret).toBe('JBSWY3DPEHPK3PXP')
  })

  // This URI is the second QR code (batchIndex=1, batchSize=2) from a separate
  // 2-QR export session. REAL_URI is a distinct standalone export (batchSize=1)
  // and cannot be combined with it — the missing piece is the first QR of this
  // same 2-QR session (batchIndex=0).
  it('returns incomplete-batch for the second QR of a 2-QR export when first is absent', () => {
    const secondQr =
      'otpauth-migration://offline?data=CiYKCkhlnGhvcd7dvvASBlRlc3QyMxoKU2FsZXNmb3JjZSABKAEwAhACGAIgAQ%3D%3D'

    const result = normalizeImport(secondQr)
    expect(result.status).toBe('incomplete-batch')
    expect(result.expected).toBe(2)
    expect(result.received).toBe(1)
    expect(result.batchId).toBe(0)
  })
})

describe('normalizeImport — standard otpauth URIs', () => {
  it('normalises a single TOTP URI', () => {
    const result = normalizeImport(
      'otpauth://totp/alice%40example.com?secret=JBSWY3DP&issuer=Example'
    )

    expect(result.status).toBe('complete')
    expect(result.records).toHaveLength(1)
    expect(result.records[0]).toMatchObject({
      type: 'TOTP',
      label: 'alice@example.com',
      issuer: 'Example',
      secret: 'JBSWY3DP'
    })
  })

  it('normalises multiple otpauth URIs', () => {
    const uris = [
      'otpauth://totp/alice?secret=JBSWY3DP',
      'otpauth://hotp/bob?secret=JBSWY3DP&counter=0'
    ]
    const result = normalizeImport(uris)
    expect(result.status).toBe('complete')
    expect(result.records).toHaveLength(2)
    expect(result.records[0].type).toBe('TOTP')
    expect(result.records[1].type).toBe('HOTP')
  })
})

describe('normalizeImport — invalid input', () => {
  it('throws on unrecognised format', () => {
    expect(() => normalizeImport('not-a-valid-uri')).toThrow()
  })

  it('throws on empty array', () => {
    expect(() => normalizeImport([])).toThrow()
  })
})
