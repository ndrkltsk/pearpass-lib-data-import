/**
 * Minimal SubtleCrypto polyfill for environments that lack crypto.subtle
 * (e.g., React Native). Implements only the methods kdbxweb needs:
 * digest, importKey, sign, encrypt, decrypt.
 *
 * On desktop/browser where crypto.subtle already exists, this is a no-op.
 * Dependencies are loaded conditionally to avoid pulling in node:crypto
 * on platforms that don't need the polyfill.
 */

if (!globalThis.crypto) {
  globalThis.crypto = {}
}

if (!globalThis.crypto.getRandomValues) {
  try {
    const { getRandomValues } = require('expo-crypto')
    globalThis.crypto.getRandomValues = getRandomValues
  } catch {
    throw new Error(
      'crypto.getRandomValues is not available. Install expo-crypto or react-native-get-random-values.'
    )
  }
}

if (!globalThis.crypto.subtle) {
  const { sha256 } = require('@noble/hashes/sha256')
  const { sha512 } = require('@noble/hashes/sha512')
  const { hmac } = require('@noble/hashes/hmac')
  const { pbkdf2 } = require('@noble/hashes/pbkdf2')
  const { cbc } = require('@noble/ciphers/aes')

  const toUint8 = (data) => {
    if (data instanceof Uint8Array) return data
    if (data instanceof ArrayBuffer) return new Uint8Array(data)
    if (ArrayBuffer.isView(data)) {
      return new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    }
    throw new TypeError('Expected ArrayBuffer or TypedArray')
  }

  const algName = (alg) => (typeof alg === 'string' ? alg : alg?.name || '')

  const toBuffer = (uint8) =>
    uint8.buffer.slice(uint8.byteOffset, uint8.byteOffset + uint8.byteLength)

  class PolyfillCryptoKey {
    constructor(raw, algorithm) {
      this.rawKey = toUint8(raw)
      this.algorithm = algorithm
    }
  }

  globalThis.crypto.subtle = {
    async digest(algorithm, data) {
      const name = algName(algorithm)
      const input = toUint8(data)
      if (name === 'SHA-256') return toBuffer(sha256(input))
      if (name === 'SHA-512') return toBuffer(sha512(input))
      throw new Error(`Unsupported digest: ${name}`)
    },

    async importKey(format, keyData, algorithm, extractable, usages) {
      if (format !== 'raw') throw new Error(`Unsupported format: ${format}`)
      return new PolyfillCryptoKey(keyData, algorithm, usages)
    },

    async sign(algorithm, key, data) {
      if (algName(algorithm) !== 'HMAC') {
        throw new Error('Only HMAC sign is supported')
      }
      const hashAlg = algName(key.algorithm?.hash || key.algorithm)
      const hashFn =
        hashAlg === 'SHA-256' ? sha256 : hashAlg === 'SHA-512' ? sha512 : null
      if (!hashFn) throw new Error(`Unsupported HMAC hash: ${hashAlg}`)
      return toBuffer(hmac(hashFn, key.rawKey, toUint8(data)))
    },

    async encrypt(algorithm, key, data) {
      if (algName(algorithm) !== 'AES-CBC') {
        throw new Error('Only AES-CBC encrypt is supported')
      }
      return toBuffer(
        cbc(key.rawKey, toUint8(algorithm.iv)).encrypt(toUint8(data))
      )
    },

    async decrypt(algorithm, key, data) {
      if (algName(algorithm) !== 'AES-CBC') {
        throw new Error('Only AES-CBC decrypt is supported')
      }
      return toBuffer(
        cbc(key.rawKey, toUint8(algorithm.iv)).decrypt(toUint8(data))
      )
    },

    async deriveBits(algorithm, key, length) {
      if (algName(algorithm) !== 'PBKDF2') {
        throw new Error('Only PBKDF2 is supported for deriveBits')
      }
      const hashAlg = algName(algorithm.hash)
      const hashFn =
        hashAlg === 'SHA-256' ? sha256 : hashAlg === 'SHA-512' ? sha512 : null
      if (!hashFn) throw new Error(`Unsupported PBKDF2 hash: ${hashAlg}`)
      const result = pbkdf2(hashFn, key.rawKey, toUint8(algorithm.salt), {
        c: algorithm.iterations,
        dkLen: length / 8
      })
      return toBuffer(result)
    }
  }
}
