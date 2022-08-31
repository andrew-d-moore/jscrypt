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
 * Encryption library
 *
 * @author Andrew Moore <amoore@mutesol.com>
 * @version 0.1.0
 */
export default class Crypt {
  /**
   * Generate a uuid string
   *
   * @returns {string} uuid string.
   */
  public static generateUUID(): string { return crypto.randomUUID({ disableEntropyCache: true })}

  /**
   * Check UUID is valid
   * @param {string} id UUID string
   * @returns {boolean} True if string is valid UUID
   */
  public static isValidUUID(id: string): boolean {
    let regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    if (regex.test(id)) return true
    else return false
  }

  /**
   * Generate a salt string
   *
   * @param {number} bytes Number of bytes to use
   * in salt, default 32.
   * @returns {string} Salt string.
   */
  public static generateSalt(bytes: number = 32): string { return crypto.randomBytes(bytes).toString('base64url') }

  /**
   * Generate an HMAC string hash
   *
   * @param {configHMAC} config string to be hashed as well as
   * configurations for the type of hash.
   * @returns {string} Hashed string.
   */
  public static generateHMAC(config: configHMAC): string {
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
  public static base64url_encode(string: string): string {
    return Buffer.from(string).toString('base64url')
  }

  /**
   * Decode string from base64url_encode string
   *
   * @param {string} string base64url string.
   * @returns {string} Returns ascii string.
   */
  public static base64url_decode(string: string): string {
    return Buffer.from(string, 'base64url').toString('ascii')
  }

  /**
   * String Hashing object - String to Integer
   * Determinisitic
   *
   * @author Andrew Moore <amoore@mutesol.com>
   * @version 1.0.0
   */
  public static hashStringToInt: any = class {
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
    public hash(): number { return this._hash }

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
   *
   * @author Andrew Moore <amoore@mutesol.com>
   * @version 1.0.0
   */
  public static hashStringPbkdf2Sync: any = class {
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
    public getHash(): object {
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
    public getResult(): boolean { return this._match }

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
}

export { configHMAC, configPbkdf2Sync }