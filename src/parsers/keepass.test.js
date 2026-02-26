/**
 * @jest-environment jsdom
 */
import {
  parseKeePassCsv,
  parseKeePassXml,
  parseKeePassData,
  decryptKeePassKdbx
} from './keepass'
import { addHttps } from '../utils/addHttps'

jest.mock('../utils/addHttps', () => ({
  addHttps: jest.fn((url) => `https://${url.replace(/^https?:\/\//, '')}`)
}))

jest.mock('kdbxweb', () => {
  class ProtectedValue {
    constructor(text) {
      this._text = text
    }
    getText() {
      return this._text
    }
    static fromString(str) {
      return new ProtectedValue(str)
    }
  }

  return {
    Credentials: jest.fn(),
    ProtectedValue,
    Kdbx: {
      load: jest.fn()
    },
    CryptoEngine: {
      setArgon2Impl: jest.fn()
    },
    Consts: {
      KdfId: { Argon2id: 'argon2id' },
      ErrorCodes: { InvalidKey: 'InvalidKey' }
    }
  }
})

jest.mock('hash-wasm', () => ({
  argon2id: jest.fn(),
  argon2d: jest.fn()
}))

const kdbxweb = require('kdbxweb')

describe('parseKeePassCsv', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('parses basic 5-column CSV correctly', () => {
    const csv = `"Account","Login Name","Password","Web Site","Comments"
"My Bank","user@example.com","s3cret","bank.com","Banking login"`
    const result = parseKeePassCsv(csv)
    expect(result).toEqual([
      {
        type: 'login',
        folder: null,
        isFavorite: false,
        data: {
          title: 'My Bank',
          username: 'user@example.com',
          password: 's3cret',
          note: 'Banking login',
          websites: ['https://bank.com'],
          customFields: []
        }
      }
    ])
    expect(addHttps).toHaveBeenCalledWith('bank.com')
  })

  it('parses multiple entries', () => {
    const csv = `"Account","Login Name","Password","Web Site","Comments"
"Site1","user1","pass1","site1.com","Note1"
"Site2","user2","pass2","site2.com","Note2"`
    const result = parseKeePassCsv(csv)
    expect(result.length).toBe(2)
    expect(result[0].data.title).toBe('Site1')
    expect(result[1].data.title).toBe('Site2')
  })

  it('handles empty fields', () => {
    const csv = `"Account","Login Name","Password","Web Site","Comments"
"","","","",""`
    const result = parseKeePassCsv(csv)
    expect(result[0].data.title).toBe('')
    expect(result[0].data.username).toBe('')
    expect(result[0].data.password).toBe('')
    expect(result[0].data.websites).toEqual([])
    expect(result[0].data.note).toBe('')
  })

  it('handles special characters in fields', () => {
    const csv = `"Account","Login Name","Password","Web Site","Comments"
"My ""Special"" Site","user,name","pass""word","example.com","A note, with commas"`
    const result = parseKeePassCsv(csv)
    expect(result[0].data.title).toBe('My "Special" Site')
    expect(result[0].data.username).toBe('user,name')
    expect(result[0].data.password).toBe('pass"word')
    expect(result[0].data.note).toBe('A note, with commas')
  })

  it('returns empty array for header-only CSV', () => {
    const csv = `"Account","Login Name","Password","Web Site","Comments"`
    expect(parseKeePassCsv(csv)).toEqual([])
  })

  it('all entries are login type with isFavorite false', () => {
    const csv = `"Account","Login Name","Password","Web Site","Comments"
"Site","user","pass","site.com",""
"Site2","user2","pass2","site2.com",""`
    const result = parseKeePassCsv(csv)
    result.forEach((entry) => {
      expect(entry.type).toBe('login')
      expect(entry.isFavorite).toBe(false)
      expect(entry.folder).toBeNull()
    })
  })
})

describe('parseKeePassCsv - KeePassXC format', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('parses basic KeePassXC CSV correctly', () => {
    const csv = `"Group","Title","Username","Password","URL","Notes","TOTP"
"Internet","Gmail","user@gmail.com","s3cret","gmail.com","My email",""`
    const result = parseKeePassCsv(csv)
    expect(result).toEqual([
      {
        type: 'login',
        folder: 'Internet',
        isFavorite: false,
        data: {
          title: 'Gmail',
          username: 'user@gmail.com',
          password: 's3cret',
          note: 'My email',
          websites: ['https://gmail.com'],
          customFields: []
        }
      }
    ])
  })

  it('parses multiple KeePassXC entries', () => {
    const csv = `"Group","Title","Username","Password","URL","Notes","TOTP"
"Email","Gmail","user1","pass1","gmail.com","",""
"Social","Twitter","user2","pass2","twitter.com","",""
"Banking","My Bank","user3","pass3","bank.com","Main account",""`
    const result = parseKeePassCsv(csv)
    expect(result.length).toBe(3)
    expect(result[0].data.title).toBe('Gmail')
    expect(result[0].folder).toBe('Email')
    expect(result[1].data.title).toBe('Twitter')
    expect(result[1].folder).toBe('Social')
    expect(result[2].data.title).toBe('My Bank')
    expect(result[2].folder).toBe('Banking')
  })

  it('maps TOTP field to customFields', () => {
    const csv = `"Group","Title","Username","Password","URL","Notes","TOTP"
"","TOTP Entry","user","pass","example.com","","otpauth://totp/test?secret=JBSWY3DPEHPK3PXP"`
    const result = parseKeePassCsv(csv)
    expect(result[0].data.customFields).toEqual([
      {
        type: 'note',
        note: 'TOTP: otpauth://totp/test?secret=JBSWY3DPEHPK3PXP'
      }
    ])
  })

  it('handles empty group as null folder', () => {
    const csv = `"Group","Title","Username","Password","URL","Notes","TOTP"
"","Root Entry","user","pass","","",""`
    const result = parseKeePassCsv(csv)
    expect(result[0].folder).toBeNull()
  })

  it('preserves "Root" group as folder', () => {
    const csv = `"Group","Title","Username","Password","URL","Notes","TOTP"
"Root","FB","user@gmail.com","pass123","","",""`
    const result = parseKeePassCsv(csv)
    expect(result[0].folder).toBe('Root')
  })

  it('handles empty fields in KeePassXC format', () => {
    const csv = `"Group","Title","Username","Password","URL","Notes","TOTP"
"","","","","","",""`
    const result = parseKeePassCsv(csv)
    expect(result[0].data.title).toBe('')
    expect(result[0].data.username).toBe('')
    expect(result[0].data.password).toBe('')
    expect(result[0].data.websites).toEqual([])
    expect(result[0].data.note).toBe('')
    expect(result[0].data.customFields).toEqual([])
  })

  it('all KeePassXC entries are login type with isFavorite false', () => {
    const csv = `"Group","Title","Username","Password","URL","Notes","TOTP"
"Group1","Site1","user1","pass1","site1.com","",""
"Group2","Site2","user2","pass2","site2.com","",""`
    const result = parseKeePassCsv(csv)
    result.forEach((entry) => {
      expect(entry.type).toBe('login')
      expect(entry.isFavorite).toBe(false)
    })
  })
})

describe('parseKeePassCsv - auto-detection', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('auto-detects KeePass 1.x format from headers', () => {
    const csv = `"Account","Login Name","Password","Web Site","Comments"
"My Site","user","pass","site.com","A note"`
    const result = parseKeePassCsv(csv)
    expect(result[0].data.title).toBe('My Site')
    expect(result[0].data.username).toBe('user')
    expect(result[0].folder).toBeNull()
  })

  it('auto-detects KeePassXC format from headers', () => {
    const csv = `"Group","Title","Username","Password","URL","Notes","TOTP"
"Internet","My Site","user","pass","site.com","A note",""`
    const result = parseKeePassCsv(csv)
    expect(result[0].data.title).toBe('My Site')
    expect(result[0].data.username).toBe('user')
    expect(result[0].folder).toBe('Internet')
  })

  it('falls back to KeePassXC format for unknown headers', () => {
    const csv = `"Folder","Name","User","Pass","Link","Info"
"Test","Entry","u","p","test.com","info"`
    const result = parseKeePassCsv(csv)
    // Falls back to KeePassXC parser which maps by header position
    expect(result.length).toBe(1)
  })
})

describe('parseKeePassXml', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('parses basic XML entry', () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>Root</Name>
      <Entry>
        <String><Key>Title</Key><Value>Test Entry</Value></String>
        <String><Key>UserName</Key><Value>testuser</Value></String>
        <String><Key>Password</Key><Value>testpass</Value></String>
        <String><Key>URL</Key><Value>example.com</Value></String>
        <String><Key>Notes</Key><Value>A test note</Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>`
    const result = parseKeePassXml(xml)
    expect(result).toEqual([
      {
        type: 'login',
        folder: 'Root',
        isFavorite: false,
        data: {
          title: 'Test Entry',
          username: 'testuser',
          password: 'testpass',
          note: 'A test note',
          websites: ['https://example.com'],
          customFields: []
        }
      }
    ])
  })

  it('preserves nested group folder paths', () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>Root</Name>
      <Group>
        <Name>Internet</Name>
        <Group>
          <Name>Banking</Name>
          <Entry>
            <String><Key>Title</Key><Value>My Bank</Value></String>
            <String><Key>UserName</Key><Value>user</Value></String>
            <String><Key>Password</Key><Value>pass</Value></String>
            <String><Key>URL</Key><Value></Value></String>
            <String><Key>Notes</Key><Value></Value></String>
          </Entry>
        </Group>
      </Group>
    </Group>
  </Root>
</KeePassFile>`
    const result = parseKeePassXml(xml)
    expect(result[0].folder).toBe('Root/Internet/Banking')
  })

  it('extracts custom fields', () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>Root</Name>
      <Entry>
        <String><Key>Title</Key><Value>Entry</Value></String>
        <String><Key>UserName</Key><Value>user</Value></String>
        <String><Key>Password</Key><Value>pass</Value></String>
        <String><Key>URL</Key><Value></Value></String>
        <String><Key>Notes</Key><Value></Value></String>
        <String><Key>Recovery Email</Key><Value>backup@example.com</Value></String>
        <String><Key>PIN</Key><Value>1234</Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>`
    const result = parseKeePassXml(xml)
    expect(result[0].data.customFields).toEqual([
      { type: 'note', note: 'Recovery Email: backup@example.com' },
      { type: 'note', note: 'PIN: 1234' }
    ])
  })

  it('handles TOTP fields', () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>Root</Name>
      <Entry>
        <String><Key>Title</Key><Value>TOTP Entry</Value></String>
        <String><Key>UserName</Key><Value>user</Value></String>
        <String><Key>Password</Key><Value>pass</Value></String>
        <String><Key>URL</Key><Value></Value></String>
        <String><Key>Notes</Key><Value></Value></String>
        <String><Key>TOTP Seed</Key><Value>JBSWY3DPEHPK3PXP</Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>`
    const result = parseKeePassXml(xml)
    expect(result[0].data.customFields).toEqual([
      { type: 'note', note: 'TOTP: JBSWY3DPEHPK3PXP' }
    ])
  })

  it('handles entries with missing fields', () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>Root</Name>
      <Entry>
        <String><Key>Title</Key><Value>Minimal</Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>`
    const result = parseKeePassXml(xml)
    expect(result[0].data.title).toBe('Minimal')
    expect(result[0].data.username).toBe('')
    expect(result[0].data.password).toBe('')
    expect(result[0].data.websites).toEqual([])
    expect(result[0].data.note).toBe('')
  })

  it('throws on invalid XML', () => {
    expect(() => parseKeePassXml('<not-keepass></not-keepass>')).toThrow(
      'Invalid KeePass XML file'
    )
  })

  it('returns empty array when no entries exist', () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>Root</Name>
    </Group>
  </Root>
</KeePassFile>`
    const result = parseKeePassXml(xml)
    expect(result).toEqual([])
  })

  it('handles entries in multiple groups', () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>Root</Name>
      <Entry>
        <String><Key>Title</Key><Value>Root Entry</Value></String>
        <String><Key>UserName</Key><Value></Value></String>
        <String><Key>Password</Key><Value></Value></String>
        <String><Key>URL</Key><Value></Value></String>
        <String><Key>Notes</Key><Value></Value></String>
      </Entry>
      <Group>
        <Name>Email</Name>
        <Entry>
          <String><Key>Title</Key><Value>Gmail</Value></String>
          <String><Key>UserName</Key><Value>user@gmail.com</Value></String>
          <String><Key>Password</Key><Value>gmailpass</Value></String>
          <String><Key>URL</Key><Value>gmail.com</Value></String>
          <String><Key>Notes</Key><Value></Value></String>
        </Entry>
      </Group>
      <Group>
        <Name>Social</Name>
        <Entry>
          <String><Key>Title</Key><Value>Twitter</Value></String>
          <String><Key>UserName</Key><Value>@me</Value></String>
          <String><Key>Password</Key><Value>twitterpass</Value></String>
          <String><Key>URL</Key><Value>twitter.com</Value></String>
          <String><Key>Notes</Key><Value></Value></String>
        </Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>`
    const result = parseKeePassXml(xml)
    expect(result.length).toBe(3)
    expect(result[0].folder).toBe('Root')
    expect(result[0].data.title).toBe('Root Entry')
    expect(result[1].folder).toBe('Root/Email')
    expect(result[1].data.title).toBe('Gmail')
    expect(result[2].folder).toBe('Root/Social')
    expect(result[2].data.title).toBe('Twitter')
  })
})

describe('decryptKeePassKdbx', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('returns the root group from the decrypted KDBX database', async () => {
    const mockFields = new Map([
      ['Title', 'Test Login'],
      ['UserName', 'testuser'],
      ['Password', 'testpass'],
      ['URL', 'example.com'],
      ['Notes', 'A note']
    ])

    const mockRootGroup = {
      name: 'Root',
      entries: [{ fields: mockFields }],
      groups: []
    }

    kdbxweb.Kdbx.load.mockResolvedValue({ groups: [mockRootGroup] })

    const result = await decryptKeePassKdbx(new ArrayBuffer(10), 'password')
    expect(result).toEqual(mockRootGroup)
  })

  it('returns the root group with nested subgroups intact', async () => {
    const makeFields = (title) =>
      new Map([
        ['Title', title],
        ['UserName', ''],
        ['Password', ''],
        ['URL', ''],
        ['Notes', '']
      ])

    const mockRootGroup = {
      name: 'Root',
      entries: [],
      groups: [
        {
          name: 'Internet',
          entries: [{ fields: makeFields('Web Entry') }],
          groups: [
            {
              name: 'Banking',
              entries: [{ fields: makeFields('Bank Entry') }],
              groups: []
            }
          ]
        }
      ]
    }

    kdbxweb.Kdbx.load.mockResolvedValue({ groups: [mockRootGroup] })

    const result = await decryptKeePassKdbx(new ArrayBuffer(10), 'password')
    expect(result).toEqual(mockRootGroup)
  })

  it('returns the root group containing entries with TOTP fields', async () => {
    const mockFields = new Map([
      ['Title', 'TOTP Entry'],
      ['UserName', 'user'],
      ['Password', 'pass'],
      ['URL', ''],
      ['Notes', ''],
      ['TOTP Seed', 'JBSWY3DPEHPK3PXP'],
      ['otp', 'otpauth://totp/test']
    ])

    const mockRootGroup = {
      name: 'Root',
      entries: [{ fields: mockFields }],
      groups: []
    }

    kdbxweb.Kdbx.load.mockResolvedValue({ groups: [mockRootGroup] })

    const result = await decryptKeePassKdbx(new ArrayBuffer(10), 'password')
    expect(result).toEqual(mockRootGroup)
  })

  it('returns the root group containing entries with non-standard custom fields', async () => {
    const mockFields = new Map([
      ['Title', 'Entry'],
      ['UserName', 'user'],
      ['Password', 'pass'],
      ['URL', ''],
      ['Notes', ''],
      ['Recovery Email', 'backup@test.com'],
      ['Security Question', 'Pet name']
    ])

    const mockRootGroup = {
      name: 'Root',
      entries: [{ fields: mockFields }],
      groups: []
    }

    kdbxweb.Kdbx.load.mockResolvedValue({ groups: [mockRootGroup] })

    const result = await decryptKeePassKdbx(new ArrayBuffer(10), 'password')
    expect(result).toEqual(mockRootGroup)
  })

  it('returns the root group containing entries with ProtectedValue fields', async () => {
    const protectedPassword = new kdbxweb.ProtectedValue('secret123')
    const mockFields = new Map([
      ['Title', 'Entry'],
      ['UserName', 'user'],
      ['Password', protectedPassword],
      ['URL', ''],
      ['Notes', '']
    ])

    const mockRootGroup = {
      name: 'Root',
      entries: [{ fields: mockFields }],
      groups: []
    }

    kdbxweb.Kdbx.load.mockResolvedValue({ groups: [mockRootGroup] })

    const result = await decryptKeePassKdbx(new ArrayBuffer(10), 'password')
    expect(result).toEqual(mockRootGroup)
  })

  it('throws "Incorrect password" on InvalidKey error', async () => {
    const error = new Error('Invalid key')
    error.code = 'InvalidKey'
    kdbxweb.Kdbx.load.mockRejectedValue(error)

    await expect(
      decryptKeePassKdbx(new ArrayBuffer(10), 'wrong')
    ).rejects.toThrow('Incorrect password')
  })

  it('throws with original error message on other errors', async () => {
    kdbxweb.Kdbx.load.mockRejectedValue(new Error('Random error'))

    await expect(
      decryptKeePassKdbx(new ArrayBuffer(10), 'pass')
    ).rejects.toThrow('Failed to open database: Random error')
  })
})

describe('parseKeePassData', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('routes CSV to parseKeePassCsv', async () => {
    const csv = `"Account","Login Name","Password","Web Site","Comments"
"Site","user","pass","site.com","note"`
    const result = await parseKeePassData(csv, 'csv')
    expect(result[0].data.title).toBe('Site')
    expect(result[0].type).toBe('login')
  })

  it('routes XML to parseKeePassXml', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>Root</Name>
      <Entry>
        <String><Key>Title</Key><Value>XML Entry</Value></String>
        <String><Key>UserName</Key><Value>user</Value></String>
        <String><Key>Password</Key><Value>pass</Value></String>
        <String><Key>URL</Key><Value></Value></String>
        <String><Key>Notes</Key><Value></Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>`
    const result = await parseKeePassData(xml, 'xml')
    expect(result[0].data.title).toBe('XML Entry')
  })

  it('routes KDBX group to walkGroup', async () => {
    const rootGroup = {
      name: 'Root',
      entries: [
        {
          fields: new Map([
            ['Title', 'KDBX Entry'],
            ['UserName', ''],
            ['Password', ''],
            ['URL', ''],
            ['Notes', '']
          ])
        }
      ],
      groups: []
    }

    const result = await parseKeePassData(rootGroup, 'kdbx')
    expect(result[0].data.title).toBe('KDBX Entry')
  })

  it('throws for unsupported file type', async () => {
    await expect(parseKeePassData('data', 'json')).rejects.toThrow(
      'Unsupported file type'
    )
  })
})
