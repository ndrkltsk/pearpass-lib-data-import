import { normalizeProtonAuthenticator } from './normalize'

const EXPORT = JSON.stringify({
  version: 1,
  entries: [
    {
      id: '4a4cd5aa-1662-4582-91cf-a2be2d53aa35',
      content: {
        uri: 'otpauth://totp/test?secret=QWEA&issuer=&algorithm=SHA1&digits=6&period=30',
        entry_type: 'Totp',
        name: 'test'
      },
      note: null
    },
    {
      id: '1d5a9064-eb80-4d0a-acde-c0ee8218d330',
      content: {
        uri: 'otpauth://totp/qwqe?secret=QWQEQ&issuer=facebook&algorithm=SHA1&digits=6&period=30',
        entry_type: 'Totp',
        name: 'qwqe'
      },
      note: null
    }
  ]
})

describe('normalizeProtonAuthenticator', () => {
  it('returns one OTPRecord per entry', () => {
    const records = normalizeProtonAuthenticator(EXPORT)
    expect(records).toHaveLength(2)
  })

  it('maps label from URI path', () => {
    const records = normalizeProtonAuthenticator(EXPORT)
    expect(records[0].label).toBe('test')
    expect(records[1].label).toBe('qwqe')
  })

  it('maps issuer when present in URI', () => {
    const records = normalizeProtonAuthenticator(EXPORT)
    expect(records[1].issuer).toBe('facebook')
  })

  it('maps type, algorithm, digits, and period', () => {
    const [record] = normalizeProtonAuthenticator(EXPORT)
    expect(record.type).toBe('TOTP')
    expect(record.algorithm).toBe('SHA1')
    expect(record.digits).toBe(6)
    expect(record.period).toBe(30)
  })

  it('normalises the secret to uppercase', () => {
    const [record] = normalizeProtonAuthenticator(EXPORT)
    expect(record.secret).toBe(record.secret.toUpperCase())
  })

  describe('error handling', () => {
    it('throws on invalid JSON', () => {
      expect(() => normalizeProtonAuthenticator('not json')).toThrow(
        'normalizeProtonAuthenticator: invalid JSON'
      )
    })

    it('throws when entries array is missing', () => {
      expect(() =>
        normalizeProtonAuthenticator(JSON.stringify({ version: 1 }))
      ).toThrow('missing or invalid "entries" array')
    })

    it('throws when an entry has no uri', () => {
      const bad = JSON.stringify({
        version: 1,
        entries: [
          { id: 'x', content: { entry_type: 'Totp', name: 'x' }, note: null }
        ]
      })
      expect(() => normalizeProtonAuthenticator(bad)).toThrow(
        'entry at index 0 has no valid otpauth:// URI'
      )
    })

    it('throws when uri does not start with otpauth://', () => {
      const bad = JSON.stringify({
        version: 1,
        entries: [
          {
            id: 'x',
            content: {
              uri: 'https://example.com',
              entry_type: 'Totp',
              name: 'x'
            },
            note: null
          }
        ]
      })
      expect(() => normalizeProtonAuthenticator(bad)).toThrow(
        'entry at index 0 has no valid otpauth:// URI'
      )
    })
  })
})
