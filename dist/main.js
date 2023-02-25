"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Crypt = void 0;
/**
 * Crypto wrapper
 *
 * @license @Mutable Solutions, LLC
 * @author Andrew Moore <amoore@mutesol.com>
 * @version 0.1.0
 */
const crypt_1 = __importDefault(require("./crypt/crypt"));
exports.Crypt = crypt_1.default;
console.log(crypt_1.default.generateUUID());
console.log(crypt_1.default.generateSalt(64));
const testTime = () => {
    setTimeout(() => {
        console.log(Date.now());
        testTime();
    }, 1000);
};
//testTime()
//# sourceMappingURL=main.js.map