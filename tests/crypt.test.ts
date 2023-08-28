import Crypt from '../src/crypt/crypt'
import { Users } from 'jadt'

describe('generateUUID', () => {
  it('Should return vaid uuid', () => {
    let t = Crypt.generateUUID()
    let regex = /^[a-z,0-9,-]{36,36}$/;
    expect(regex.test(t)).toBeTruthy()
  })
})

describe('isValidUUID', () => {
  it('should return true for valid UUIDs', () => {
    expect(Crypt.isValidUUID('123e4567-e89b-12d3-a456-426614174000')).toBe(true)
  })

  it('should return false for invalid UUIDs', () => {
    expect(Crypt.isValidUUID('invalid-uuid')).toBe(false)
  })
})

describe('generateSalt', () => {
  it('should generate a salt of the specified length', () => {
    const salt = Crypt.generateSalt(16)
    expect(salt).toHaveLength(22)
  })

  it('should generate a salt of the default length if no length is specified', () => {
    const salt = Crypt.generateSalt()
    expect(salt).toHaveLength(43)
  })
})

describe('generateHMAC', () => {
  it('Should match HMAC string hash', () => {
    let t = Crypt.generateHMAC({ string: 'test' })
    expect(t).toBe("Aymga2LNFrM-tnkr6MYLFY2Jou46h2_Omogeu0iMCRQ")
  })
  it('Should match HMAC string hash', () => {
    let t = Crypt.generateHMAC({
      string: 'test',
      algorithm: `sha256`,
      encoding: `base64url`
    })
    expect(t).toBe("Aymga2LNFrM-tnkr6MYLFY2Jou46h2_Omogeu0iMCRQ")
  })
})

describe('base64url_encode', () => {
  it('should encode a string in base64url format', () => {
    const encodedString = Crypt.base64url_encode('test string')
    expect(encodedString).toBe('dGVzdCBzdHJpbmc')
  })
})

describe('base64url_decode', () => {
  it('should decode a base64url encoded string', () => {
    const decodedString = Crypt.base64url_decode('dGVzdCBzdHJpbmc')
    expect(decodedString).toBe('test string')
  })
})

describe('hashStringToInt', () => {
  it('should hash a string to an integer', () => {
    const hashStringToInt = new Crypt.hashStringToInt('test string', 100, 31)
    const hash = hashStringToInt.hash()
    expect(hash).toBe(33)
  })
})

describe('hashStringPbkdf2Sync', () => {
  it('Should create hash object', () => {
    const hash = new Crypt.hashStringToInt(Users.user1.id, 257, 11)
    expect(hash).toBeInstanceOf(Crypt.hashStringToInt)
  })

  it('Return hashed string', () => {
    const hash = new Crypt.hashStringToInt(Users.user1.id, 257, 11)
    expect(hash.hash()).toBe(93)
  })

  it('Should return hash object', () => {
    const hash = new Crypt.hashStringPbkdf2Sync({
      string: 'testPassword',
    })
    expect(hash.getHash()).toBeInstanceOf(Object)
  })

  it('Should return true', () => {
    const hash = new Crypt.hashStringPbkdf2Sync({
      string: 'testPassword',
      encoding: `base64url`,
      iterations: 10000,
      keylength: 64,
      algorithm: `sha512`
    })
    const hash2 = new Crypt.hashStringPbkdf2Sync({
      string: 'testPassword',
      hash: hash.getHash().hash,
      salt: hash.getHash().salt,
      encoding: `base64url`,
      iterations: 10000,
      keylength: 64,
      algorithm: `sha512`
    })
    expect(hash2.getResult()).toBeTruthy()
  })
})

describe('diffieHellman', () => {
  let instance
  beforeEach(() => {
    instance = new Crypt.diffieHellman()
  })

  describe('init', () => {
    test('returns an object with public and private keys for userA and userB', async () => {
      const result = await instance.init()
      expect(result).toHaveProperty('KeysA')
      expect(result.KeysA).toHaveProperty('public')
      expect(result.KeysA).toHaveProperty('private')
      expect(result).toHaveProperty('KeysB')
      expect(result.KeysB).toHaveProperty('public')
      expect(result.KeysB).toHaveProperty('private')
    })
  })

  describe('verifyKeys', () => {
    test('returns true when userASharedKey and userBSharedKey are equal', async () => {
      await instance.init()
      expect(instance.verifyKeys()).toBe(true)
    })
  })
})

describe('rsa', () => {
  describe('generateKeyPair', () => {
    test('returns an object with publicKey and privateKey properties', () => {
      const result = Crypt.generateRSAKeyPair()
      expect(result).toHaveProperty('publicKey')
      expect(result).toHaveProperty('privateKey')
    })

    test('returns different keys when called with different passphrases', () => {
      const result1 = Crypt.generateRSAKeyPair('passphrase1')
      const result2 = Crypt.generateRSAKeyPair('passphrase2')
      expect(result1.publicKey).not.toEqual(result2.publicKey)
      expect(result1.privateKey).not.toEqual(result2.privateKey)
    })
  })

  let publicKey, privateKey;
  beforeEach(() => {
    const result = Crypt.generateRSAKeyPair()
    publicKey = result.publicKey
    privateKey = result.privateKey
  })

  describe('encryptData', () => {
    test('returns a Buffer', () => {
      const data = 'Hello, world!'
      const result = Crypt.encryptDataRSA(publicKey, data)
      expect(result).toBeInstanceOf(Buffer)
    })
  })

  describe('decryptData', () => {
    test('returns the original data when called with the correct private key', () => {
      const data = 'Hello, world!'
      const encryptedData = Crypt.encryptDataRSA(publicKey, data)
      const result = Crypt.decryptDataRSA(privateKey, encryptedData)
      expect(result.toString()).toEqual(data)
    })
  })

  describe('signData', () => {
    test('returns a Buffer', () => {
      const data = 'Hello, world!'
      const result = Crypt.signDataRSA(privateKey, data)
      expect(result).toBeInstanceOf(Buffer)
    })
  })

  describe('verifySignature', () => {
    test('returns true when called with the correct public key and signature', () => {
      const data = 'Hello, world!'
      const signature = Crypt.signDataRSA(privateKey, data)
      const result = Crypt.verifySignatureRSA(publicKey, data, signature)
      expect(result).toBe(true)
    })
  })
})

const crypto = require('crypto')

describe('encryptDataGCM and decryptDataGCM', () => {
  const sharedKey = crypto.randomBytes(32).toString('hex')
  const data = 'Hello, World!'

  test('should encrypt and decrypt data correctly', () => {
    const encrypted = Crypt.encryptDataGCM(sharedKey, data)
    const decrypted = Crypt.decryptDataGCM(sharedKey, encrypted)

    expect(decrypted).toBe(data)
  })
})
