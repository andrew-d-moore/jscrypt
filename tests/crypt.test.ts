import Crypt from '../src/crypt/crypt'
import { Users } from 'jadt'

test('Should return vaid uuid', () => {
  let t = Crypt.generateUUID()
  let regex = /^[a-z,0-9,-]{36,36}$/;
  expect(regex.test(t)).toBeTruthy()
})

test('Should match HMAC string hash', () => {
  let t = Crypt.generateHMAC({ string: 'test' })
  expect(t).toBe("Aymga2LNFrM-tnkr6MYLFY2Jou46h2_Omogeu0iMCRQ")
})

test('Should match HMAC string hash', () => {
  let t = Crypt.generateHMAC({
    string: 'test',
    algorithm: `sha256`,
    encoding: `base64url`
  })
  expect(t).toBe("Aymga2LNFrM-tnkr6MYLFY2Jou46h2_Omogeu0iMCRQ")
})

test('Should create hash object', () => {
  const hash = new Crypt.hashStringToInt(Users.user1.id, 257, 11)
  expect(hash).toBeInstanceOf(Crypt.hashStringToInt)
})

test('Return hashed string', () => {
  const hash = new Crypt.hashStringToInt(Users.user1.id, 257, 11)
  expect(hash.hash()).toBe(93)
})

test('Should return hash object', () => {
  const hash = new Crypt.hashStringPbkdf2Sync({
    string: 'testPassword',
  })
  expect(hash.getHash()).toBeInstanceOf(Object)
})

test('Should return true', () => {
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