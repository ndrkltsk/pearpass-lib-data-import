import { parseOtpUri } from './parseOtpUri'

describe('parseOtpUri', () => {
  describe('valid TOTP URI', () => {
    it('parses minimal TOTP URI with defaults', () => {
      const record = parseOtpUri(
        'otpauth://totp/alice%40example.com?secret=JBSWY3DP'
      )
      expect(record).toEqual({
        type: 'TOTP',
        label: 'alice@example.com',
        secret: 'JBSWY3DP',
        algorithm: 'SHA1',
        digits: 6,
        period: 30
      })
    })

    it('parses TOTP URI with all parameters', () => {
      const record = parseOtpUri(
        'otpauth://totp/Example%3Aalice%40example.com?secret=JBSWY3DP&issuer=Example&algorithm=SHA256&digits=8&period=60'
      )
      expect(record).toEqual({
        type: 'TOTP',
        label: 'alice@example.com',
        issuer: 'Example',
        secret: 'JBSWY3DP',
        algorithm: 'SHA256',
        digits: 8,
        period: 60
      })
    })

    it('parses issuer from label prefix when issuer param is absent', () => {
      const record = parseOtpUri(
        'otpauth://totp/GitHub%3Aalice?secret=JBSWY3DP'
      )
      expect(record.issuer).toBe('GitHub')
      expect(record.label).toBe('alice')
    })

    it('issuer param takes precedence over label prefix for the issuer field', () => {
      const record = parseOtpUri(
        'otpauth://totp/GitHub%3Aalice?secret=JBSWY3DP&issuer=GitHubOverride'
      )
      expect(record.issuer).toBe('GitHubOverride')
      // Label prefix is always stripped so the account name is clean
      expect(record.label).toBe('alice')
    })

    it('normalises secret to uppercase and strips spaces', () => {
      const record = parseOtpUri('otpauth://totp/test?secret=jbswy 3dp')
      expect(record.secret).toBe('JBSWY3DP')
    })
  })

  describe('valid HOTP URI', () => {
    it('parses HOTP URI with counter', () => {
      const record = parseOtpUri(
        'otpauth://hotp/alice?secret=JBSWY3DP&counter=5'
      )
      expect(record).toMatchObject({
        type: 'HOTP',
        label: 'alice',
        secret: 'JBSWY3DP',
        algorithm: 'SHA1',
        digits: 6,
        counter: 5
      })
    })

    it('defaults counter to 0 when absent', () => {
      const record = parseOtpUri('otpauth://hotp/alice?secret=JBSWY3DP')
      expect(record.counter).toBe(0)
      expect(record).not.toHaveProperty('period')
    })

    it('does not set period on HOTP records', () => {
      const record = parseOtpUri('otpauth://hotp/alice?secret=JBSWY3DP')
      expect(record).not.toHaveProperty('period')
    })
  })

  describe('errors', () => {
    it('throws on wrong protocol', () => {
      expect(() => parseOtpUri('https://example.com')).toThrow(
        'must start with otpauth://'
      )
    })

    it('throws on non-string input', () => {
      expect(() => parseOtpUri(null)).toThrow('must start with otpauth://')
    })

    it('throws on invalid OTP type', () => {
      expect(() => parseOtpUri('otpauth://steam/alice?secret=ABC')).toThrow(
        'Invalid OTP type'
      )
    })

    it('throws when secret is missing', () => {
      expect(() => parseOtpUri('otpauth://totp/alice')).toThrow(
        'missing required parameter "secret"'
      )
    })

    it('throws on unsupported algorithm', () => {
      expect(() =>
        parseOtpUri('otpauth://totp/alice?secret=ABC&algorithm=MD5')
      ).toThrow('Invalid algorithm')
    })
  })
})
