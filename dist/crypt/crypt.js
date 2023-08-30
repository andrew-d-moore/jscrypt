"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
/**
 * Encryption library
 */
class Crypt {
    /**
     * Generate a valid uuid string
     *
     * @returns {string} uuid string.
     */
    static generateUUID() { return crypto_1.default.randomUUID({ disableEntropyCache: true }); }
    /**
     * Check UUID is valid
     * @param {string} id UUID string
     * @returns {boolean} True if string is valid UUID
     */
    static isValidUUID(id) {
        let regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        if (regex.test(id))
            return true;
        else
            return false;
    }
    /**
     * Generate a salt string - default 32 bytes
     *
     * @param {number} bytes Number of bytes to use
     * in salt, default 32.
     * @returns {string} Salt string.
     */
    static generateSalt(bytes = 32) {
        return crypto_1.default.randomBytes(bytes).toString('base64url');
    }
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
    /**
     * @param passphrase
     * @returns {string, string}
     */
    static generateRSAKeyPair(passphrase) {
        // The `generateKeyPairSync` method accepts two arguments:
        // 1. The type of keys we want, which in this case is "rsa"
        // 2. An object with the properties of the key
        const { publicKey, privateKey } = crypto_1.default.generateKeyPairSync(`rsa`, {
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
                passphrase: (() => { if (passphrase)
                    return passphrase;
                else
                    return `top secret`; })()
            }
        });
        return {
            publicKey,
            privateKey
        };
    }
    /**
     * @param publicKey
     * @param data
     * @returns {Buffer}
     */
    static encryptDataRSA(publicKey, data) {
        return crypto_1.default.publicEncrypt({
            key: publicKey,
            padding: crypto_1.default.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256"
        }, Buffer.from(data));
    }
    /**
     * @param privateKey
     * @param data
     * @param passphrase
     * @returns {Buffer}
     */
    static decryptDataRSA(privateKey, data, passphrase) {
        const encryptedKey = crypto_1.default.createPrivateKey({
            key: privateKey,
            passphrase: (() => { if (passphrase)
                return passphrase;
            else
                return `top secret`; })()
        });
        return crypto_1.default.privateDecrypt({
            key: encryptedKey,
            // In order to decrypt the data, we need to specify the
            // same hashing function and padding scheme that we used to
            // encrypt the data in the previous step
            padding: crypto_1.default.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256"
        }, data);
    }
    /**
     * @param privateKey
     * @param data
     * @param passphrase
     * @returns {Buffer}
     */
    static signDataRSA(privateKey, data, passphrase) {
        const encryptedKey = crypto_1.default.createPrivateKey({
            key: privateKey,
            passphrase: (() => { if (passphrase)
                return passphrase;
            else
                return `top secret`; })()
        });
        // The signature method takes the data we want to sign, the
        // hashing algorithm, and the padding scheme, and generates
        // a signature in the form of bytes
        return crypto_1.default.sign("sha256", Buffer.from(data), {
            key: encryptedKey,
            padding: crypto_1.default.constants.RSA_PKCS1_PSS_PADDING,
        });
    }
    /**
     * @param publicKey
     * @param data
     * @param signature
     * @returns {Boolean}
     */
    static verifySignatureRSA(publicKey, data, signature) {
        // To verify the data, we provide the same hashing algorithm and
        // padding scheme we provided to generate the signature, along
        // with the signature itself, the data that we want to
        // verify against the signature, and the public key
        return crypto_1.default.verify("sha256", Buffer.from(data), {
            key: publicKey,
            padding: crypto_1.default.constants.RSA_PKCS1_PSS_PADDING,
        }, signature);
    }
    /**
     * @param sharedKey - hex string
     * @param data - POD
     * @returns {string} - base64 string
     */
    static encryptDataGCM(sharedKey, data) {
        const IV = crypto_1.default.randomBytes(16);
        const cipher = crypto_1.default.createCipheriv('aes-256-gcm', Buffer.from(sharedKey, 'hex'), IV);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const auth_tag = cipher.getAuthTag().toString('hex');
        const payload = IV.toString('hex') + encrypted + auth_tag;
        return Buffer.from(payload, 'hex').toString('base64');
    }
    /**
     * @param sharedKey - hex string
     * @param cipher - base64 string
     * @returns {string}
     */
    static decryptDataGCM(sharedKey, cipher) {
        const payload = Buffer.from(cipher, 'base64').toString('hex');
        const IV = payload.substring(0, 32);
        const encrypted = payload.substring(32, payload.length - 32);
        const auth_tag = payload.substring(payload.length - 32, payload.length);
        try {
            const decipher = crypto_1.default.createDecipheriv('aes-256-gcm', Buffer.from(sharedKey, 'hex'), Buffer.from(IV, 'hex'));
            decipher.setAuthTag(Buffer.from(auth_tag, 'hex'));
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            return decrypted += decipher.final('utf8');
        }
        catch (err) {
            return err;
        }
    }
}
exports.default = Crypt;
/**
 * String Hashing object - String to Integer
 * Determinisitic
 * @class
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
 * @class
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
/**
 * Generate shared keys using diffieHellman
 * PublicKeys encoded as base64
 * SharedKey encoded as hex
 * @class
 */
Crypt.diffieHellman = class {
    /**
     * @constructor
     * @param {configDiffieHellman} config
     */
    constructor(config) {
        this.encoding = `base64`;
        this.textEncoding = `base64`;
        this.outputEncoding = `hex`;
        if (config) {
            this.encoding = config.encoding;
            this.textEncoding = config.textEncoding;
            this.outputEncoding = config.outputEncoding;
        }
        this._userA = crypto_1.default.createECDH(`secp256k1`);
        this._userB = crypto_1.default.createECDH(`secp256k1`);
    }
    init() {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.generateKeys();
            yield this.generatePublicKeys();
            yield this.generateSharedKeys();
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
                };
            }
            else
                throw new Error(`Error generating keys`);
        });
    }
    /**
     * @async
     * @returns {Promise<void>}
     */
    generateKeys() {
        return __awaiter(this, void 0, void 0, function* () {
            this._userA.generateKeys();
            this._userB.generateKeys();
        });
    }
    /**
     * @async
     * @returns {Promise<void>}
     */
    generatePublicKeys() {
        return __awaiter(this, void 0, void 0, function* () {
            this._userAPublicKey = this._userA.getPublicKey().toString(this.encoding);
            this._userBPublicKey = this._userB.getPublicKey().toString(this.encoding);
        });
    }
    generateSharedKeys() {
        return __awaiter(this, void 0, void 0, function* () {
            this._userASharedKey = this._userA.computeSecret(this._userBPublicKey, this.textEncoding, this.outputEncoding);
            this._userBSharedKey = this._userB.computeSecret(this._userAPublicKey, this.textEncoding, this.outputEncoding);
        });
    }
    verifyKeys() {
        return (this._userASharedKey === this._userBSharedKey);
    }
};
//# sourceMappingURL=crypt.js.map