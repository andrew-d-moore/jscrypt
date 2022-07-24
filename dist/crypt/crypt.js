"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
/**
 * Encryption library
 *
 * @author Andrew Moore <amoore@mutesol.com>
 * @version 0.1.0
 */
class Crypt {
    /**
     * Generate a uuid string
     *
     * @returns {string} uuid string.
     */
    static generateUUID() { return crypto_1.default.randomUUID({ disableEntropyCache: true }); }
    /**
     * Generate a salt string
     *
     * @param {number} bytes Number of bytes to use
     * in salt, default 32.
     * @returns {string} Salt string.
     */
    static generateSalt(bytes = 32) { return crypto_1.default.randomBytes(bytes).toString('base64url'); }
    /**
     * Generate an HMAC string hash
     *
     * @param {configHMAC} config string to be hashed as well as
     * configurations for the type of hash.
     * @returns {string} Hashed string.
     */
    static generateHMAC(config) {
        let algorithm, encoding, secret;
        if (config.algorithm)
            algorithm = config.algorithm;
        else
            algorithm = 'sha256';
        if (config.encoding)
            encoding = config.encoding;
        else
            encoding = 'base64url';
        if (config.secret)
            secret = config.secret;
        else
            secret = 'secret';
        const hmac = crypto_1.default.createHmac(algorithm, secret);
        const data = hmac.update(config.string);
        const gen_hmac = data.digest(encoding);
        return gen_hmac;
    }
    /**
     * Encode string to base64url_encoded string
     *
     * @param {string} string ascii string.
     * @returns {string} Returns base64url string.
     */
    static base64url_encode(string) {
        return Buffer.from(string).toString('base64url');
    }
    /**
     * Decode string from base64url_encode string
     *
     * @param {string} string base64url string.
     * @returns {string} Returns ascii string.
     */
    static base64url_decode(string) {
        return Buffer.from(string, 'base64url').toString('ascii');
    }
}
exports.default = Crypt;
/**
 * String Hashing object - String to Integer
 * Determinisitic
 *
 * @author Andrew Moore <amoore@mutesol.com>
 * @version 1.0.0
 */
Crypt.hashStringToInt = class {
    /**
     * @param {string} string String to be hashed.
     * @param {number} range Maximum size of the integer created from hash,
     * usually the size or capacity of the array or list or other data-structure
     * to be used.
     * @param {number} prime Prime number to salt the hashing algorithm.
     */
    constructor(string, range, prime) {
        this._hash = 0;
        this.string = string, this.range = range, this.prime = prime;
        this.hashString();
    }
    /**
     * Return hashed int
     *
     * @returns {number} Hashed string as an integer.
     */
    hash() { return this._hash; }
    /**
     * Hash string to int O(n)
     */
    hashString() {
        for (let i = 0; i < this.string.length; i++)
            this._hash += (this.string.charCodeAt(i) * this.prime);
        this._hash = this._hash % this.range;
    }
};
/**
 * String Hashing object - String to hashed string
 * of designated length.
 * Semi-Determinisitic
 *
 * @author Andrew Moore <amoore@mutesol.com>
 * @version 1.0.0
 */
Crypt.hashStringPbkdf2Sync = class {
    /**
     * @param {configPbkdf2Sync} config Hash function configuration object.
     */
    constructor(config) {
        this._string = config.string;
        this.hash(config);
        if (config.hash) {
            this._hash_check = config.hash;
            this._match = this._hash_check === this._hash;
        }
    }
    /**
     * Return results of hashing function
     *
     * @returns {object} Returns object containing
     * hashed string and salt.
     */
    getHash() {
        return {
            hash: this._hash,
            salt: this._salt
        };
    }
    /**
     * Return results of hash comparison
     *
     * @returns {boolean} Truthy if the provided hash and salt
     * match the string hash.
     */
    getResult() { return this._match; }
    /**
     * Hash string with Pbkdf2Sync crypto function
     *
     * @param {configPbkdf2Sync} config Hash object configuration.
     * @returns {boolean | object} Truthy if hash to match
     * is provided and matches hashed string. Otherwise returns
     * a hashed string and salt for provided string.
     */
    hash(config) {
        this._hash = crypto_1.default.pbkdf2Sync(this._string, (() => {
            if (config.salt)
                return this._salt = config.salt;
            else
                return this._salt = crypto_1.default.randomBytes((() => {
                    if (config.randomBytes)
                        return config.randomBytes;
                    else
                        return 32;
                })()).toString((() => {
                    if (config.encoding)
                        return config.encoding;
                    else
                        return 'hex';
                })());
        })(), (() => {
            if (config.iterations)
                return config.iterations;
            else
                return 1000;
        })(), (() => {
            if (config.keylength)
                return config.keylength;
            else
                return 64;
        })(), (() => {
            if (config.algorithm)
                return config.algorithm;
            else
                return `sha512`;
        })()).toString((() => {
            if (config.encoding)
                return config.encoding;
            else
                return 'hex';
        })());
    }
};
//# sourceMappingURL=crypt.js.map