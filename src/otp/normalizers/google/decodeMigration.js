import { decodeMigrationPayload } from './protobuf.js'

/**
 * Decodes a Google Authenticator migration URI.
 *
 * URI format: otpauth-migration://offline?data=<base64-encoded-protobuf>
 *
 * @param {string} uri
 * @returns {{ otpParameters: Object[], version: number, batchSize: number, batchIndex: number, batchId: number }}
 */
const BASE64_RE = /^[A-Za-z0-9+/]+=*$/

export function decodeMigrationUri(uri) {
  if (typeof uri !== 'string' || !uri.startsWith('otpauth-migration://')) {
    throw new Error(
      'Invalid migration URI: must start with otpauth-migration://'
    )
  }

  let url
  try {
    url = new URL(uri)
  } catch {
    throw new Error('Invalid migration URI: malformed URL')
  }

  const data = url.searchParams.get('data')
  if (!data) {
    throw new Error('Invalid migration URI: missing "data" query parameter')
  }

  if (!BASE64_RE.test(data)) {
    throw new Error(
      'Invalid migration URI: "data" parameter is not valid base64'
    )
  }

  const buf = Buffer.from(data, 'base64')

  if (buf.length === 0) {
    throw new Error(
      'Invalid migration URI: "data" parameter decoded to empty buffer'
    )
  }

  return decodeMigrationPayload(buf)
}
