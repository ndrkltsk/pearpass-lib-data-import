import { normalizeGooglePayload } from './normalize'

const HELLO_BYTES = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f])

describe('normalizeGooglePayload', () => {
  it('maps a TOTP parameter to an OTPRecord', () => {
    const payload = {
      otpParameters: [
        {
          secret: HELLO_BYTES,
          name: 'alice@example.com',
          issuer: 'Example',
          type: 2,
          algorithm: 1,
          digits: 1
        }
      ]
    }
    const [record] = normalizeGooglePayload(payload)
    expect(record.type).toBe('TOTP')
    expect(record.label).toBe('alice@example.com')
    expect(record.issuer).toBe('Example')
    expect(record.secret).toBe('JBSWY3DP')
    expect(record.algorithm).toBe('SHA1')
    expect(record.digits).toBe(6)
    expect(record.period).toBe(30)
    expect(record.counter).toBeUndefined()
  })

  it('maps an HOTP parameter to an OTPRecord', () => {
    const payload = {
      otpParameters: [
        {
          secret: HELLO_BYTES,
          name: 'bob',
          type: 1,
          algorithm: 1,
          digits: 1,
          counter: 5
        }
      ]
    }
    const [record] = normalizeGooglePayload(payload)
    expect(record.type).toBe('HOTP')
    expect(record.counter).toBe(5)
    expect(record.period).toBeUndefined()
  })

  it('falls back to TOTP for unknown type 0', () => {
    const payload = {
      otpParameters: [
        { secret: HELLO_BYTES, name: 'x', type: 0, algorithm: 0, digits: 0 }
      ]
    }
    const [record] = normalizeGooglePayload(payload)
    expect(record.type).toBe('TOTP')
  })

  it('maps algorithm 2 to SHA256 and algorithm 3 to SHA512', () => {
    const base = { secret: HELLO_BYTES, name: 'x', type: 2, digits: 1 }
    const [sha256Record] = normalizeGooglePayload({
      otpParameters: [{ ...base, algorithm: 2 }]
    })
    const [sha512Record] = normalizeGooglePayload({
      otpParameters: [{ ...base, algorithm: 3 }]
    })
    expect(sha256Record.algorithm).toBe('SHA256')
    expect(sha512Record.algorithm).toBe('SHA512')
  })

  it('maps digits field: 2 → 8 digits', () => {
    const payload = {
      otpParameters: [
        { secret: HELLO_BYTES, name: 'x', type: 2, algorithm: 1, digits: 2 }
      ]
    }
    const [record] = normalizeGooglePayload(payload)
    expect(record.digits).toBe(8)
  })

  it('handles missing issuer gracefully', () => {
    const payload = {
      otpParameters: [
        {
          secret: HELLO_BYTES,
          name: 'no-issuer',
          type: 2,
          algorithm: 1,
          digits: 1
        }
      ]
    }
    const [record] = normalizeGooglePayload(payload)
    expect(record.issuer).toBeUndefined()
  })

  it('throws when secret is missing', () => {
    const payload = {
      otpParameters: [{ name: 'x', type: 2 }]
    }
    expect(() => normalizeGooglePayload(payload)).toThrow(
      'OTP parameter is missing required field: secret'
    )
  })

  it('throws when secret is empty', () => {
    const payload = {
      otpParameters: [{ secret: new Uint8Array([]), name: 'x', type: 2 }]
    }
    expect(() => normalizeGooglePayload(payload)).toThrow(
      'OTP parameter is missing required field: secret'
    )
  })

  it('returns empty array for empty otpParameters', () => {
    expect(normalizeGooglePayload({ otpParameters: [] })).toEqual([])
  })

  it('processes multiple parameters', () => {
    const payload = {
      otpParameters: [
        {
          secret: HELLO_BYTES,
          name: 'alice',
          type: 2,
          algorithm: 1,
          digits: 1
        },
        { secret: HELLO_BYTES, name: 'bob', type: 2, algorithm: 1, digits: 1 }
      ]
    }
    const records = normalizeGooglePayload(payload)
    expect(records).toHaveLength(2)
    expect(records[0].label).toBe('alice')
    expect(records[1].label).toBe('bob')
  })

  it('exposes the raw source on the record', () => {
    const params = {
      secret: HELLO_BYTES,
      name: 'x',
      type: 2,
      algorithm: 1,
      digits: 1
    }
    const [record] = normalizeGooglePayload({ otpParameters: [params] })
    expect(record.raw).toBe(params)
  })
})
