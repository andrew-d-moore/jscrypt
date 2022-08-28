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
     *
     * @author Andrew Moore <amoore@mutesol.com>
     * @version 1.0.0
     */
    static hashStringToInt: any;
    /**
     * String Hashing object - String to hashed string
     * of designated length.
     * Semi-Determinisitic
     *
     * @author Andrew Moore <amoore@mutesol.com>
     * @version 1.0.0
     */
    static hashStringPbkdf2Sync: any;
}
export { configHMAC, configPbkdf2Sync };
