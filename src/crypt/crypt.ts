import crypto, { BinaryToTextEncoding } from 'crypto'

/**
 * configHMAC Interface
 * @example
 * {
 *  'string': string,
 *  'algorithm'?: string,
 *  'encoding'?: string,
 *  'secret'?: string
 * }
 */
interface configHMAC {
  string: string,
  algorithm?: string,
  encoding?: BinaryToTextEncoding,
  secret?: string
}

/**
 * configPbkdf2Sync Interface
 * @example
 * {
 *  'string': string,
 *  'algorithm'?: string,
 *  'encoding'?: BufferEncoding,
 *  'salt'?: string,
 *  'hash'?: string,
 *  'iterations'?: number,
 *  'keylength'?: number,
 *  'randomBytes'?: number
 * }
 */
interface configPbkdf2Sync {
  string: string,
  algorithm?: string,
  encoding?: BufferEncoding,
  salt?: string,
  hash?: string,
  iterations?: number,
  keylength?: number,
  randomBytes?: number
}

/**
 * @export
 * @interface configDiffieHellman
 * @typedef {configDiffieHellman}
 * @example
 * {
 *  encoding?: BufferEncoding,
 *  textEncoding?: BinaryToTextEncoding
 *  outputEncoding?: BinaryToTextEncoding
 * }
 */
interface configDiffieHellman {
  encoding?: BufferEncoding,
  textEncoding?: BinaryToTextEncoding,
  outputEncoding?: BinaryToTextEncoding,
}

export { configHMAC, configPbkdf2Sync, configDiffieHellman }

/**
 * Encryption library
 */
export default class Crypt {
  /**
   * Generate a valid uuid string
   *
   * @returns {string} uuid string.
   */
  static generateUUID(): string { return crypto.randomUUID({ disableEntropyCache: true })}

  /**
   * Check UUID is valid
   * @param {string} id UUID string
   * @returns {boolean} True if string is valid UUID
   */
  static isValidUUID(id: string): boolean {
    let regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    if (regex.test(id)) return true
    else return false
  }

  /**
   * Generate a salt string - default 32 bytes
   *
   * @param {number} bytes Number of bytes to use
   * in salt, default 32.
   * @returns {string} Salt string.
   */
  static generateSalt(bytes: number = 32): string {
    return crypto.randomBytes(bytes).toString('base64url')
  }

  /**
   * Generate an HMAC string hash
   *
   * @param {configHMAC} config string to be hashed as well as
   * configurations for the type of hash.
   * @returns {string} Hashed string.
   */
  static generateHMAC(config: configHMAC): string {
    let algorithm: string, encoding: BinaryToTextEncoding, secret: string
    if (config.algorithm) algorithm = config.algorithm
    else algorithm = 'sha256'

    if (config.encoding) encoding = config.encoding
    else encoding = 'base64url'

    if (config.secret) secret = config.secret
    else secret = 'secret'

    const hmac = crypto.createHmac(algorithm, secret)
    const data = hmac.update(config.string)
    const gen_hmac = data.digest(encoding)
    return gen_hmac
  }

  /**
   * Encode string to base64url_encoded string
   *
   * @param {string} string ascii string.
   * @returns {string} Returns base64url string.
   */
  static base64url_encode(string: string): string {
    return Buffer.from(string).toString('base64url')
  }

  /**
   * Decode string from base64url_encode string
   *
   * @param {string} string base64url string.
   * @returns {string} Returns ascii string.
   */
  static base64url_decode(string: string): string {
    return Buffer.from(string, 'base64url').toString('ascii')
  }

  /**
   * String Hashing object - String to Integer
   * Determinisitic
   * @class
   */
  static hashStringToInt: any = class {
    _hash: number = 0
    range: number
    prime: number
    string: string
    /**
     * @param {string} string String to be hashed.
     * @param {number} range Maximum size of the integer created from hash,
     * usually the size or capacity of the array or list or other data-structure
     * to be used.
     * @param {number} prime Prime number to salt the hashing algorithm.
     */
    constructor(string: string, range: number, prime: number) {
      this.string = string, this.range = range, this.prime = prime
      this.hashString()
    }

    /**
     * Return hashed int
     *
     * @returns {number} Hashed string as an integer.
     */
    hash(): number { return this._hash }

    /**
     * Hash string to int O(n)
     */
    private hashString(): void {
      for (let i = 0; i < this.string.length; i++)
        this._hash += (this.string.charCodeAt(i) * this.prime)
      this._hash = this._hash % this.range
    }
  }

  /**
   * String Hashing object - String to hashed string
   * of designated length.
   * Semi-Determinisitic
   * @class
   */
  static hashStringPbkdf2Sync: any = class {
    _hash: string
    _salt: string
    _string: string
    _hash_check: string
    _match: boolean
    /**
     * @param {configPbkdf2Sync} config Hash function configuration object.
     */
    constructor(config: configPbkdf2Sync) {
      this._string = config.string
      this.hash(config)
      if (config.hash) {
        this._hash_check = config.hash
        this._match = this._hash_check === this._hash
      }
    }

    /**
     * Return results of hashing function
     *
     * @returns {object} Returns object containing
     * hashed string and salt.
     */
    getHash(): object {
      return {
        hash: this._hash,
        salt: this._salt
      }
    }

    /**
     * Return results of hash comparison
     *
     * @returns {boolean} Truthy if the provided hash and salt
     * match the string hash.
     */
    getResult(): boolean { return this._match }

    /**
     * Hash string with Pbkdf2Sync crypto function
     *
     * @param {configPbkdf2Sync} config Hash object configuration.
     * @returns {boolean | object} Truthy if hash to match
     * is provided and matches hashed string. Otherwise returns
     * a hashed string and salt for provided string.
     */
    private hash(config: configPbkdf2Sync): void {
      this._hash = crypto.pbkdf2Sync(
        this._string,
        (() => {
          if (config.salt) return this._salt = config.salt
          else
            return this._salt = crypto.randomBytes(
              (() => {
                if (config.randomBytes) return config.randomBytes
                else return 32
              })()
            ).toString(
              (() => {
                if (config.encoding) return config.encoding
                else return 'hex'
              })()
            )
        })(),
        (() => {
          if (config.iterations) return config.iterations
          else return 1000
        })(),
        (() => {
          if (config.keylength) return config.keylength
          else return 64
        })(),
        (() => {
          if (config.algorithm) return config.algorithm
          else return `sha512`
        })()
      ).toString(
        (() => {
          if (config.encoding) return config.encoding
          else return 'hex'
        })()
      )
    }
  }

  /**
   * Generate shared keys using diffieHellman
   * PublicKeys encoded as base64
   * SharedKey encoded as hex
   * @class
   */
  static diffieHellman: any = class {
    encoding: BufferEncoding = `base64`
    textEncoding: BinaryToTextEncoding = `base64`
    outputEncoding: BinaryToTextEncoding = `hex`
    _userA: crypto.ECDH
    _userAPublicKey: string
    _userASharedKey: string
    _userB: crypto.ECDH
    _userBPublicKey: string
    _userBSharedKey: string
    /**
     * @constructor
     * @param {configDiffieHellman} config
     */
    constructor(config?: configDiffieHellman) {
      if (config) {
        this.encoding = config.encoding
        this.textEncoding = config.textEncoding
        this.outputEncoding = config.outputEncoding
      }
      this._userA = crypto.createECDH(`secp256k1`)
      this._userB = crypto.createECDH(`secp256k1`)
    }

    async init(): Promise<any> {
      await this.generateKeys()
      await this.generatePublicKeys()
      await this.generateSharedKeys()
      if (this.verifyKeys) {
        return {
          KeysA: {
            public: this._userAPublicKey,
            private: this._userASharedKey
          },
          KeysB: {
            public: this._userBPublicKey,
            private: this._userBSharedKey
          }
        }
      } else throw new Error(`Error generating keys`)
    }

    /**
     * @async
     * @returns {Promise<void>}
     */
    async generateKeys(): Promise<void> {
      this._userA.generateKeys()
      this._userB.generateKeys()
    }

    /**
     * @async
     * @returns {Promise<void>}
     */
    async generatePublicKeys(): Promise<void> {
      this._userAPublicKey = this._userA.getPublicKey().toString(this.encoding)
      this._userBPublicKey = this._userB.getPublicKey().toString(this.encoding)
    }

    async generateSharedKeys(): Promise<void> {
      this._userASharedKey = this._userA.computeSecret(
        this._userBPublicKey,
        this.textEncoding,
        this.outputEncoding
      )
      this._userBSharedKey = this._userB.computeSecret(
        this._userAPublicKey,
        this.textEncoding,
        this.outputEncoding
      )
    }

    verifyKeys(): boolean {
      return (this._userASharedKey === this._userBSharedKey)
    }
  }

  /**
   * @param passphrase
   * @returns {string, string}
   */
  static generateRSAKeyPair(passphrase?: string): { publicKey: string, privateKey: string } {
    // The `generateKeyPairSync` method accepts two arguments:
    // 1. The type of keys we want, which in this case is "rsa"
    // 2. An object with the properties of the key
    const { publicKey, privateKey } = crypto.generateKeyPairSync(`rsa`, {
      // The standard secure default length for RSA keys is 2048 bits
      modulusLength: 4096,
      publicKeyEncoding: {
        type: `spki`,
        format: `pem`
      },
      privateKeyEncoding: {
        type: `pkcs8`,
        format: `pem`,
        cipher: `aes-256-cbc`,
        passphrase: (() => { if (passphrase) return passphrase; else return `top secret` })()
      }
    })

    return {
      publicKey,
      privateKey
    }
  }

  /**
   * @param publicKey
   * @param data
   * @returns {Buffer}
   */
  static encryptDataRSA(publicKey: string, data: any): Buffer {
    return crypto.publicEncrypt({
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    },
      Buffer.from(data)
    )
  }

  /**
   * @param privateKey
   * @param data
   * @param passphrase
   * @returns {Buffer}
   */
  static decryptDataRSA(privateKey: string, data: any, passphrase?: string): Buffer {
    const encryptedKey = crypto.createPrivateKey({
      key: privateKey,
      passphrase: (() => { if (passphrase) return passphrase; else return `top secret` })()
    })
    return crypto.privateDecrypt({
        key: encryptedKey,
		    // In order to decrypt the data, we need to specify the
		    // same hashing function and padding scheme that we used to
		    // encrypt the data in the previous step
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      data
    )
  }

  /**
   * @param privateKey
   * @param data
   * @param passphrase
   * @returns {Buffer}
   */
  static signDataRSA(privateKey: string, data: any, passphrase?: string): Buffer {
    const encryptedKey = crypto.createPrivateKey({
      key: privateKey,
      passphrase: (() => { if (passphrase) return passphrase; else return `top secret` })()
    })

    // The signature method takes the data we want to sign, the
    // hashing algorithm, and the padding scheme, and generates
    // a signature in the form of bytes
    return crypto.sign(
      "sha256",
      Buffer.from(data),
      {
        key: encryptedKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      }
    )
  }

  /**
   * @param publicKey
   * @param data
   * @param signature
   * @returns {Boolean}
   */
  static verifySignatureRSA(publicKey: string, data: any, signature: Buffer): Boolean {
    // To verify the data, we provide the same hashing algorithm and
    // padding scheme we provided to generate the signature, along
    // with the signature itself, the data that we want to
    // verify against the signature, and the public key
    return crypto.verify(
      "sha256",
      Buffer.from(data),
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      },
      signature
    )
  }

  /**
   * @param sharedKey - hex string
   * @param data - POD
   * @returns {string} - base64 string
   */
  static encryptDataGCM(sharedKey: string, data: any): string {
    const IV = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(sharedKey, 'hex'), IV)

    let encrypted = cipher.update(data, 'utf8', 'hex')
    encrypted += cipher.final('hex')

    const auth_tag = cipher.getAuthTag().toString('hex')

    const payload = IV.toString('hex') + encrypted + auth_tag

    return Buffer.from(payload, 'hex').toString('base64')
  }

  /**
   * @param sharedKey - hex string
   * @param cipher - base64 string
   * @returns {string}
   */
  static decryptDataGCM(sharedKey: string, cipher: string): string {
    const payload = Buffer.from(cipher, 'base64').toString('hex')

    const IV = payload.substring(0, 32)
    const encrypted = payload.substring(32, payload.length - 32)
    const auth_tag = payload.substring(payload.length - 32, payload.length)

     try {
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        Buffer.from(sharedKey, 'hex'),
        Buffer.from(IV, 'hex')
      )
      decipher.setAuthTag(Buffer.from(auth_tag, 'hex'))

      let decrypted = decipher.update(encrypted, 'hex', 'utf8')
      return decrypted += decipher.final('utf8')
    } catch (err) { return err }
  }
}