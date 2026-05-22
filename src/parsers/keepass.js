import { argon2d, argon2id } from '@noble/hashes/argon2'
import { DOMParser as XmlDomParser } from '@xmldom/xmldom'
import * as _kdbxweb from 'kdbxweb'
import '../utils/setupCrypto.js'

const kdbxweb = _kdbxweb.default || _kdbxweb

import { addHttps } from '../utils/addHttps'
import { getRowsFromCsv } from '../utils/getRowsFromCsv'

// ---------------------------------------------------------------------------
// KDBX 4 Argon2 key derivation
//
// kdbxweb derives the master key through a single global `setArgon2Impl` hook.
// Argon2 is deliberately memory-hard; the pure-JS implementation below runs on
// the caller's thread, which on React Native's Hermes engine (no JIT) can
// freeze the UI for minutes on a KDBX 4 database. `decryptKeePassKdbx` accepts
// an optional `argon2ViaWorklet` hook so the host can offload the derivation
// to a Bare worklet (JIT-enabled V8) instead — see pearpass-lib-vault-core.
// ---------------------------------------------------------------------------

const hasBuffer = typeof Buffer !== 'undefined'

const toBase64 = (bytes) => {
  if (hasBuffer) return Buffer.from(bytes).toString('base64')
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

const fromBase64 = (b64) => {
  if (hasBuffer) return new Uint8Array(Buffer.from(b64, 'base64'))
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
}

const argon2TypeName = (type) =>
  type === kdbxweb.CryptoEngine.Argon2TypeArgon2id ? 'argon2id' : 'argon2d'

/**
 * Pure-JS Argon2 implementation for `kdbxweb.CryptoEngine.setArgon2Impl`.
 * Runs on the caller's thread — slow on Hermes; the fallback used when no
 * worklet hook is supplied.
 */
const nobleArgon2Impl = (
  password,
  salt,
  memory,
  iterations,
  length,
  parallelism,
  type,
  version
) => {
  const hashFn =
    type === kdbxweb.CryptoEngine.Argon2TypeArgon2id ? argon2id : argon2d
  return Promise.resolve(
    hashFn(new Uint8Array(password), new Uint8Array(salt), {
      t: iterations,
      m: memory,
      p: parallelism,
      dkLen: length,
      version
    })
  )
}

/**
 * Builds an Argon2 implementation that delegates the memory-hard derivation to
 * a worklet, keeping the JS thread responsive. kdbxweb passes `memory` already
 * in KiB and `length` fixed at 32.
 *
 * @param {(params: {
 *   password: string, salt: string, type: 'argon2d'|'argon2id',
 *   memory: number, iterations: number, parallelism: number,
 *   length: number, version: number
 * }) => Promise<string>} argon2ViaWorklet - resolves to a base64 derived key
 */
const createWorkletArgon2Impl =
  (argon2ViaWorklet) =>
  async (
    password,
    salt,
    memory,
    iterations,
    length,
    parallelism,
    type,
    version
  ) => {
    const derivedB64 = await argon2ViaWorklet({
      password: toBase64(new Uint8Array(password)),
      salt: toBase64(new Uint8Array(salt)),
      type: argon2TypeName(type),
      memory,
      iterations,
      parallelism,
      length,
      version
    })
    return fromBase64(derivedB64)
  }

const STANDARD_FIELDS = new Set([
  'Title',
  'UserName',
  'Password',
  'URL',
  'Notes'
])

const TOTP_FIELDS = new Set([
  'otp',
  'TOTP Settings',
  'TOTP Seed',
  'TimeOtp-Secret-Base32'
])

/**
 * Extracts text from a KDBX field value, handling ProtectedValue instances.
 * @param {string | kdbxweb.ProtectedValue} value
 * @returns {string}
 */
const getFieldText = (value) => {
  if (!value) return ''
  if (value instanceof kdbxweb.ProtectedValue) return value.getText()
  return String(value)
}

/**
 * Recursively walks a KDBX group tree and extracts entries.
 * @param {object} group - A kdbxweb group object.
 * @param {string} parentPath - Accumulated folder path from parent groups.
 * @returns {Array<object>}
 */
const walkGroup = (group, parentPath = '') => {
  const results = []
  const groupName = group.name || ''
  const currentPath = parentPath ? `${parentPath}/${groupName}` : groupName

  for (const entry of group.entries || []) {
    const fields = entry.fields || new Map()

    const title = getFieldText(fields.get('Title'))
    const username = getFieldText(fields.get('UserName'))
    const password = getFieldText(fields.get('Password'))
    const url = getFieldText(fields.get('URL'))
    const notes = getFieldText(fields.get('Notes'))

    const customFields = []

    for (const [key, value] of fields) {
      if (STANDARD_FIELDS.has(key)) continue

      const text = getFieldText(value)
      if (!text) continue

      if (TOTP_FIELDS.has(key)) {
        customFields.push({ type: 'note', note: `TOTP: ${text}` })
      } else {
        customFields.push({ type: 'note', note: `${key}: ${text}` })
      }
    }

    results.push({
      type: 'login',
      folder: currentPath || null,
      isFavorite: false,
      data: {
        title,
        username,
        password,
        note: notes,
        websites: url ? [addHttps(url)] : [],
        customFields
      }
    })
  }

  for (const subGroup of group.groups || []) {
    results.push(...walkGroup(subGroup, currentPath))
  }

  return results
}

/**
 * Parses a KDBX (KeePass 2.x) encrypted database file.
 * @param {ArrayBuffer} arrayBuffer - Raw KDBX file contents.
 * @param {string} password - Master password for decryption.
 * @param {Object} [options]
 * @param {(params: {
 *   password: string, salt: string, type: 'argon2d'|'argon2id',
 *   memory: number, iterations: number, parallelism: number,
 *   length: number, version: number
 * }) => Promise<string>} [options.argon2ViaWorklet] - Offloads the Argon2 KDF
 *   to a worklet (resolves to a base64 derived key). When omitted, a pure-JS
 *   Argon2 runs on the caller's thread.
 * @returns {Promise<object>}
 */
export const decryptKeePassKdbx = async (
  arrayBuffer,
  password,
  { argon2ViaWorklet } = {}
) => {
  // kdbxweb's Argon2 impl is global module state; register it per call so the
  // choice of worklet vs pure-JS is deterministic for each import.
  kdbxweb.CryptoEngine.setArgon2Impl(
    argon2ViaWorklet
      ? createWorkletArgon2Impl(argon2ViaWorklet)
      : nobleArgon2Impl
  )

  let db
  try {
    const credentials = new kdbxweb.Credentials(
      kdbxweb.ProtectedValue.fromString(password)
    )
    db = await kdbxweb.Kdbx.load(
      new Uint8Array(arrayBuffer).buffer,
      credentials
    )
  } catch (error) {
    if (
      error?.code === kdbxweb.Consts.ErrorCodes.InvalidKey ||
      error?.message?.includes('InvalidKey') ||
      error?.message?.includes('Invalid key') ||
      error?.message?.includes('invalid key') ||
      error?.code === 'InvalidKey'
    ) {
      throw new Error('Incorrect password')
    }
    throw new Error(`Failed to open database: ${error.message || error}`)
  }

  const rootGroup = db.groups[0]
  if (!rootGroup) return []

  return rootGroup
}

/**
 * Parses KeePass 1.x CSV export format.
 * Columns: "Account","Login Name","Password","Web Site","Comments"
 * @param {string[]} headerRow
 * @param {string[][]} dataRows
 * @returns {Array<object>}
 */
const parseKeePass1xCsv = (headerRow, dataRows) => {
  const get = (row, name) =>
    row[headerRow.indexOf(name)]?.replace(/^"|"$/g, '').trim() || ''

  return dataRows.map((row) => {
    const url = get(row, 'Web Site')

    return {
      type: 'login',
      folder: null,
      isFavorite: false,
      data: {
        title: get(row, 'Account'),
        username: get(row, 'Login Name'),
        password: get(row, 'Password'),
        note: get(row, 'Comments'),
        websites: url ? [addHttps(url)] : [],
        customFields: []
      }
    }
  })
}

/**
 * Parses KeePassXC CSV export format.
 * Columns: "Group","Title","Username","Password","URL","Notes","TOTP",...
 * @param {string[]} headerRow
 * @param {string[][]} dataRows
 * @returns {Array<object>}
 */
const parseKeePassXCCsv = (headerRow, dataRows) => {
  const headers = headerRow.map((h) => h.trim().toLowerCase())

  return dataRows.map((row) => {
    const item = Object.fromEntries(
      headers.map((key, i) => [key, row[i]?.trim() ?? ''])
    )

    const url = item.url || ''
    const totp = item.totp || ''

    const customFields = totp ? [{ type: 'note', note: `TOTP: ${totp}` }] : []

    return {
      type: 'login',
      folder: item.group || null,
      isFavorite: false,
      data: {
        title: item.title || '',
        username: item.username || '',
        password: item.password || '',
        note: item.notes || '',
        websites: url ? [addHttps(url)] : [],
        customFields
      }
    }
  })
}

/**
 * Parses a KeePass/KeePassXC CSV export, auto-detecting the format from headers.
 * @param {string} text - Raw CSV file contents.
 * @returns {Array<object>}
 */
export const parseKeePassCsv = (text) => {
  const rows = getRowsFromCsv(text)
  const [headerRow, ...dataRows] = rows

  if (!headerRow || dataRows.length === 0) return []

  const normalizedHeaders = headerRow.map((h) => h.trim().toLowerCase())

  if (
    normalizedHeaders.includes('title') &&
    normalizedHeaders.includes('username')
  ) {
    return parseKeePassXCCsv(headerRow, dataRows)
  }

  if (
    normalizedHeaders.includes('account') &&
    normalizedHeaders.includes('login name')
  ) {
    return parseKeePass1xCsv(headerRow, dataRows)
  }

  return parseKeePassXCCsv(headerRow, dataRows)
}

/** Finds the first direct child element with the given tag name. */
const findChild = (parent, tagName) => {
  for (let i = 0; i < parent.childNodes.length; i++) {
    const child = parent.childNodes[i]
    if (child.nodeType === 1 && child.tagName === tagName) return child
  }
  return null
}

/** Finds all direct child elements with the given tag name. */
const filterChildren = (parent, tagName) => {
  const result = []
  for (let i = 0; i < parent.childNodes.length; i++) {
    const child = parent.childNodes[i]
    if (child.nodeType === 1 && child.tagName === tagName) result.push(child)
  }
  return result
}

/**
 * Creates a DOMParser, using native browser DOMParser if available,
 * falling back to @xmldom/xmldom for React Native.
 */
const createXmlParser = () => {
  if (typeof globalThis.DOMParser !== 'undefined') {
    return new globalThis.DOMParser()
  }
  return new XmlDomParser({
    errorHandler: {
      warning: () => {},
      error: (msg) => {
        throw new Error(msg)
      },
      fatalError: (msg) => {
        throw new Error(msg)
      }
    }
  })
}

/**
 * Recursively walks an XML Group element tree and extracts entries.
 * Uses DOM Level 2 methods (childNodes/tagName) for xmldom compatibility.
 * @param {Element} groupElement
 * @param {string} parentPath - Accumulated folder path from parent groups.
 * @returns {Array<object>}
 */
const walkXmlGroup = (groupElement, parentPath = '') => {
  const results = []

  const nameEl = findChild(groupElement, 'Name')
  const groupName = nameEl?.textContent || ''
  const currentPath = parentPath ? `${parentPath}/${groupName}` : groupName

  const entries = filterChildren(groupElement, 'Entry')

  for (const entry of entries) {
    const strings = filterChildren(entry, 'String')

    const fields = {}
    for (const str of strings) {
      const keyEl = findChild(str, 'Key')
      const valueEl = findChild(str, 'Value')
      if (keyEl) {
        fields[keyEl.textContent] = valueEl?.textContent || ''
      }
    }

    const url = fields.URL || ''
    const customFields = []

    for (const [key, value] of Object.entries(fields)) {
      if (STANDARD_FIELDS.has(key)) continue
      if (!value) continue
      if (TOTP_FIELDS.has(key)) {
        customFields.push({ type: 'note', note: `TOTP: ${value}` })
      } else {
        customFields.push({ type: 'note', note: `${key}: ${value}` })
      }
    }

    results.push({
      type: 'login',
      folder: currentPath || null,
      isFavorite: false,
      data: {
        title: fields.Title || '',
        username: fields.UserName || '',
        password: fields.Password || '',
        note: fields.Notes || '',
        websites: url ? [addHttps(url)] : [],
        customFields
      }
    })
  }

  const subGroups = filterChildren(groupElement, 'Group')

  for (const subGroup of subGroups) {
    results.push(...walkXmlGroup(subGroup, currentPath))
  }

  return results
}

/**
 * Parses a KeePass/KeePassXC XML export.
 * @param {string} text - Raw XML file contents.
 * @returns {Array<object>}
 */
export const parseKeePassXml = (text) => {
  let doc
  try {
    const parser = createXmlParser()
    doc = parser.parseFromString(text, 'text/xml')
  } catch {
    throw new Error('Invalid KeePass XML file')
  }

  // Browser DOMParser wraps errors in <parsererror>
  if (doc.getElementsByTagName('parsererror').length > 0) {
    throw new Error('Invalid KeePass XML file')
  }

  const keepassFile = doc.getElementsByTagName('KeePassFile')[0]
  if (!keepassFile) {
    throw new Error('Invalid KeePass XML file')
  }

  const root = findChild(keepassFile, 'Root')
  if (!root) {
    throw new Error('Invalid KeePass XML file')
  }

  const rootGroup = findChild(root, 'Group')
  if (!rootGroup) return []

  return walkXmlGroup(rootGroup, '')
}

/**
 * Routes to the appropriate parser based on file type.
 * @param {string | ArrayBuffer} data - File contents (text for CSV/XML, ArrayBuffer for KDBX).
 * @param {string} fileType - One of 'kdbx', 'csv', or 'xml'.
 * @returns {Promise<Array<object>>}
 */
export const parseKeePassData = async (data, fileType) => {
  if (fileType === 'kdbx') {
    return walkGroup(data, '')
  }

  if (fileType === 'csv') {
    return parseKeePassCsv(data)
  }

  if (fileType === 'xml') {
    return parseKeePassXml(data)
  }

  throw new Error('Unsupported file type, please use KDBX, CSV, or XML')
}
