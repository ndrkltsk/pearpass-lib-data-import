import { cbc } from '@noble/ciphers/aes'
import { argon2id } from '@noble/hashes/argon2'
import { expand } from '@noble/hashes/hkdf'
import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha256'
import '../utils/setupCrypto.js'

import { addHttps } from '../utils/addHttps'
import { getRowsFromCsv } from '../utils/getRowsFromCsv'

// ---------------------------------------------------------------------------
// Bitwarden encrypted-export decryption helpers
// ---------------------------------------------------------------------------

const fromBase64 = (b64) => {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(b64, 'base64'))
  }
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
}

const toUtf8 = (str) => new TextEncoder().encode(str)

const timingSafeEqual = (a, b) => {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/**
 * Splits a Bitwarden CipherString of the form "2.iv_b64|ct_b64|mac_b64".
 * @param {string} cipherString
 * @returns {{ iv: Uint8Array, ct: Uint8Array, mac: Uint8Array }}
 */
const parseCipherString = (cipherString) => {
  const dot = cipherString.indexOf('.')
  const type = parseInt(cipherString.slice(0, dot), 10)
  if (type !== 2) throw new Error(`Unsupported CipherString type: ${type}`)
  const parts = cipherString.slice(dot + 1).split('|')
  if (parts.length !== 3) throw new Error('Invalid CipherString format')
  return {
    iv: fromBase64(parts[0]),
    ct: fromBase64(parts[1]),
    mac: fromBase64(parts[2])
  }
}

/**
 * Verifies the HMAC then decrypts an AES-256-CBC CipherString.
 * @param {string} cipherString
 * @param {Uint8Array} encKey
 * @param {Uint8Array} macKey
 * @returns {string} Decrypted UTF-8 string
 */
const aesCbcDecrypt = (cipherString, encKey, macKey) => {
  const { iv, ct, mac } = parseCipherString(cipherString)

  const expectedMac = hmac(sha256, macKey, new Uint8Array([...iv, ...ct]))
  if (!timingSafeEqual(expectedMac, mac)) {
    throw new Error('Incorrect password')
  }

  const plainBytes = cbc(encKey, iv).decrypt(ct)
  return new TextDecoder().decode(plainBytes)
}

/**
 * Decrypts a Bitwarden password-protected encrypted JSON export.
 * Supports both PBKDF2 SHA-256 (kdfType 0) and Argon2id (kdfType 1).
 *
 * @param {string} encryptedText - Raw contents of the encrypted .json file
 * @param {string} password - The password used to protect the export
 * @returns {Promise<object>} Decrypted vault JSON (pass to parseBitwardenJson)
 * @throws {Error} If the file is not password-protected or the password is wrong
 */
export const decryptBitwardenJson = async (encryptedText, password) => {
  const json = JSON.parse(encryptedText)

  if (!json.encrypted || !json.passwordProtected) {
    throw new Error('File is not password-protected')
  }

  // Bitwarden encodes the base64 salt string as UTF-8 bytes — it does NOT decode it
  const salt = toUtf8(json.salt)
  const passwordBytes = toUtf8(password)
  const kdfType = json.kdfType ?? 0

  let masterKey
  if (kdfType === 0) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    )
    const derivedBits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: json.kdfIterations, hash: 'SHA-256' },
      keyMaterial,
      256
    )
    masterKey = new Uint8Array(derivedBits)
  } else if (kdfType === 1) {
    // Argon2id: Bitwarden pre-hashes the salt with SHA-256
    const saltHashed = sha256(salt)
    masterKey = argon2id(passwordBytes, saltHashed, {
      t: json.kdfIterations,
      m: (json.kdfMemory ?? 64) * 1024,
      p: json.kdfParallelism ?? 4,
      dkLen: 32
    })
  } else {
    throw new Error(`Unsupported KDF type: ${kdfType}`)
  }

  const encKey = expand(sha256, masterKey, toUtf8('enc'), 32)
  const macKey = expand(sha256, masterKey, toUtf8('mac'), 32)

  const decryptedText = aesCbcDecrypt(json.data, encKey, macKey)
  return JSON.parse(decryptedText)
}

/**
 * @returns {string}
 */
const getFullName = (identity) =>
  [identity?.firstName, identity?.middleName, identity?.lastName]
    .filter(Boolean)
    .join(' ')

/**
 * @param {object} json
 * @param {Array<object>} [json.folders]
 * @param {string} json.folders[].id
 * @param {string} json.folders[].name
 * @param {Array<object>} [json.items]
 * @param {number} json.items[].type
 * @param {string} json.items[].name
 * @param {string} [json.items[].notes]
 * @param {boolean} [json.items[].favorite]
 * @param {string} [json.items[].folderId]
 * @param {object} [json.items[].login]
 * @param {string} [json.items[].login.username]
 * @param {string} [json.items[].login.password]
 * @param {Array<object>} [json.items[].login.uris]
 * @param {string} json.items[].login.uris[].uri
 * @param {object} [json.items[].card]
 * @param {string} [json.items[].card.cardholderName]
 * @param {string} [json.items[].card.number]
 * @param {string} [json.items[].card.expMonth]
 * @param {string} [json.items[].card.expYear]
 * @param {string} [json.items[].card.code]
 * @param {object} [json.items[].identity]
 * @param {string} [json.items[].identity.email]
 * @param {string} [json.items[].identity.phone]
 * @param {string} [json.items[].identity.address1]
 * @param {string} [json.items[].identity.address2]
 * @param {string} [json.items[].identity.address3]
 * @param {string} [json.items[].identity.postalCode]
 * @param {string} [json.items[].identity.city]
 * @param {string} [json.items[].identity.state]
 * @param {string} [json.items[].identity.country]
 * @param {string} [json.items[].identity.passportNumber]
 * @param {string} [json.items[].identity.licenseNumber]
 * @param {string} [json.items[].identity.ssn]
 * @returns {Array<{type: string, data: object, folder: string|null, isFavorite: boolean}>}
 */
export const parseBitwardenJson = (json) => {
  const folders = Object.fromEntries(
    (json.folders || []).map((f) => [f.id, f.name])
  )

  return (json.items || []).map((item) => {
    const {
      type,
      name,
      notes,
      favorite,
      folderId,
      fields,
      login,
      card,
      identity,
      sshKey
    } = item

    const folder = folders[folderId] || null
    let entryType = 'custom'
    let data = {}

    const customFields = (fields || []).map((field) => ({
      type: 'note',
      note: `${field.name}: ${field.value}`
    }))

    switch (type) {
      case 1:
        entryType = 'login'
        data = {
          title: name,
          username: login?.username || '',
          password: login?.password || '',
          note: notes || '',
          websites: (login?.uris || []).map((u) => addHttps(u.uri)),
          customFields: [
            ...customFields,
            ...(login?.totp
              ? [{ type: 'note', note: `TOTP: ${login.totp}` }]
              : [])
          ]
        }
        break

      case 2:
        entryType = 'note'
        data = {
          title: name,
          note: notes || '',
          customFields
        }
        break

      case 3:
        entryType = 'creditCard'
        data = {
          title: name,
          name: card?.cardholderName || '',
          number: (card?.number || '').replace(/\s/g, ''),
          expireDate: card
            ? `${card.expMonth ? String(card.expMonth).padStart(2, '0') : '__'} ${(card.expYear || '__').slice(-2)}`
            : '',
          securityCode: card?.code || '',
          pinCode: '',
          note: notes || '',
          customFields
        }
        break

      case 4:
        entryType = 'identity'
        data = {
          title: name,
          fullName: getFullName(identity),
          email: identity?.email || '',
          phoneNumber: identity?.phone || '',
          address: [identity?.address1, identity?.address2, identity?.address3]
            .filter(Boolean)
            .join(', '),
          zip: identity?.postalCode || '',
          city: identity?.city || '',
          region: identity?.state || '',
          country: identity?.country || '',
          passportNumber: identity?.passportNumber || '',
          drivingLicenseNumber: identity?.licenseNumber || '',
          note: notes || '',
          customFields: [
            ...(identity?.title
              ? [{ type: 'note', note: `Title: ${identity.title}` }]
              : []),
            ...(identity?.username
              ? [{ type: 'note', note: `Username: ${identity.username}` }]
              : []),
            ...(identity?.ssn
              ? [{ type: 'note', note: `SSN: ${identity.ssn}` }]
              : []),
            ...customFields
          ]
        }
        break

      case 5:
        entryType = 'custom'
        data = {
          title: name,
          customFields: [
            { type: 'note', note: notes },
            ...customFields,
            ...(sshKey
              ? Object.entries(sshKey).map(([key, value]) => ({
                  type: 'note',
                  note: `${key}: ${value}`
                }))
              : [])
          ]
        }
        break

      default:
        entryType = 'custom'
        data = {
          title: name,
          customFields
        }
    }
    return {
      type: entryType,
      data,
      folder,
      isFavorite: Boolean(favorite)
    }
  })
}

/**
 * @param {string} csvText
 * @returns {Array<{type: 'login'|'note'|'custom', data: object, folder: string, isFavorite: boolean}>}
 */
export const parseBitwardenCSV = (csvText) => {
  const rows = getRowsFromCsv(csvText)
  const [headerRow, ...dataRows] = rows

  const headers = headerRow.map((h) => h.trim())
  const entries = []

  for (const row of dataRows) {
    const item = Object.fromEntries(
      headers.map((key, i) => [key, row[i]?.trim() ?? ''])
    )

    const { folder, favorite, type, name, notes, login_totp, fields } = item

    const customFields = fields
      ? fields
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean)
          .map((line) => ({ type: 'note', note: line }))
      : []

    let entryType = 'custom'
    let data = {}

    switch (type) {
      case 'login':
        entryType = 'login'
        data = {
          title: name,
          username: item.login_username || '',
          password: item.login_password || '',
          note: notes || '',
          websites: (item.login_uri || '')
            .split(',')
            .map((uri) => uri.trim())
            .filter(Boolean)
            .map((website) => addHttps(website)),
          customFields: [
            ...customFields,
            ...(login_totp
              ? [{ type: 'note', note: `TOTP: ${login_totp}` }]
              : [])
          ]
        }
        break

      case 'note':
        entryType = 'note'
        data = {
          title: name,
          note: notes || '',
          customFields
        }
        break

      default:
        entryType = 'custom'
        data = {
          title: name,
          customFields
        }
        break
    }

    entries.push({
      type: entryType,
      data,
      folder: folder || '',
      isFavorite: favorite.toLowerCase() === 'true'
    })
  }

  return entries
}

/**
 * @param {string} data
 * @param {'json' | 'csv'} fileType
 * @returns {any}
 * @throws {Error}
 */
export const parseBitwardenData = (data, fileType) => {
  if (fileType === 'json') {
    return parseBitwardenJson(
      typeof data === 'string' ? JSON.parse(data) : data
    )
  }

  if (fileType === 'csv') {
    return parseBitwardenCSV(data)
  }

  throw new Error('Unsupported file type, please use JSON or CSV')
}
