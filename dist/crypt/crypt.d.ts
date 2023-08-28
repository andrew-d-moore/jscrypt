/// <reference types="node" />
/// <reference types="node" />
import { BinaryToTextEncoding } from 'crypto';
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
    string: string;
    algorithm?: string;
    encoding?: BinaryToTextEncoding;
    secret?: string;
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
    string: string;
    algorithm?: string;
    encoding?: BufferEncoding;
    salt?: string;
    hash?: string;
    iterations?: number;
    keylength?: number;
    randomBytes?: number;
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
    encoding?: BufferEncoding;
    textEncoding?: BinaryToTextEncoding;
    outputEncoding?: BinaryToTextEncoding;
}
export { configHMAC, configPbkdf2Sync, configDiffieHellman };
/**
 * Encryption library
 */
export default class Crypt {
    /**
     * Generate a uuid string
     *
     * @returns {string} uuid string.
     */
    static generateUUID(): string;
    /**
     * Check UUID is valid
     * @param {string} id UUID string
     * @returns {boolean} True if string is valid UUID
     */
    static isValidUUID(id: string): boolean;
    /**
     * Generate a salt string
     *
     * @param {number} bytes Number of bytes to use
     * in salt, default 32.
     * @returns {string} Salt string.
     */
    static generateSalt(bytes?: number): string;
    /**
     * Generate an HMAC string hash
     *
     * @param {configHMAC} config string to be hashed as well as
     * configurations for the type of hash.
     * @returns {string} Hashed string.
     */
    static generateHMAC(config: configHMAC): string;
    /**
     * Encode string to base64url_encoded string
     *
     * @param {string} string ascii string.
     * @returns {string} Returns base64url string.
     */
    static base64url_encode(string: string): string;
    /**
     * Decode string from base64url_encode string
     *
     * @param {string} string base64url string.
     * @returns {string} Returns ascii string.
     */
    static base64url_decode(string: string): string;
    /**
     * String Hashing object - String to Integer
     * Determinisitic
     * @class
     */
    static hashStringToInt: any;
    /**
     * String Hashing object - String to hashed string
     * of designated length.
     * Semi-Determinisitic
     * @class
     */
    static hashStringPbkdf2Sync: any;
    /**
     * Generate shared keys using diffieHellman
     * PublicKeys encoded as base64
     * SharedKey encoded as hex
     * @class
     */
    static diffieHellman: any;
    /**
     * @param passphrase
     * @returns {string, string}
     */
    static generateRSAKeyPair(passphrase?: string): {
        publicKey: string;
        privateKey: string;
    };
    /**
     * @param publicKey
     * @param data
     * @returns {Buffer}
     */
    static encryptDataRSA(publicKey: string, data: any): Buffer;
    /**
     * @param privateKey
     * @param data
     * @param passphrase
     * @returns {Buffer}
     */
    static decryptDataRSA(privateKey: string, data: any, passphrase?: string): Buffer;
    /**
     * @param privateKey
     * @param data
     * @param passphrase
     * @returns {Buffer}
     */
    static signDataRSA(privateKey: string, data: any, passphrase?: string): Buffer;
    /**
     * @param publicKey
     * @param data
     * @param signature
     * @returns {Boolean}
     */
    static verifySignatureRSA(publicKey: string, data: any, signature: Buffer): Boolean;
    /**
     * @param sharedKey - hex string
     * @param data - POD
     * @returns {string} - base64 string
     */
    static encryptDataGCM(sharedKey: string, data: any): string;
    /**
     * @param sharedKey - hex string
     * @param cipher - base64 string
     * @returns {string}
     */
    static decryptDataGCM(sharedKey: string, cipher: string): string;
}
