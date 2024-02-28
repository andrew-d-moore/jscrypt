/**
 * Crypto wrapper
 *
 * @license @Mutable Solutions, LLC
 * @author Andrew Moore <amoore@mutesol.com>
 * @version 1.0.0
 */
import Crypt, { configHMAC, configPbkdf2Sync, configDiffieHellman } from './crypt/crypt'
export { Crypt, configHMAC, configPbkdf2Sync, configDiffieHellman }

/*const keys = Crypt.generateRSAKeyPair(`s0t33hcS!`)
const keys2 = Crypt.generateRSAKeyPair()
const crypt = Crypt.encryptDataRSA(keys.publicKey, "secret data")
const crypt2 = Crypt.encryptDataRSA(keys2.publicKey, "secret data2")
const decrypt = Crypt.decryptDataRSA(keys.privateKey, crypt, 's0t33hcS!')
const decrypt2 = Crypt.decryptDataRSA(keys2.privateKey, crypt2)
const signed = Crypt.signDataRSA(keys.privateKey, crypt, 's0t33hcS!')
const verified = Crypt.verifySignatureRSA(keys.publicKey, crypt, signed)
console.log(keys)
console.log(keys2)
console.log(crypt.toString('base64'))
console.log(crypt2.toString('base64'))
console.log(decrypt.toString())
console.log(decrypt2.toString())
console.log(signed.toString('base64'))
console.log(verified)*/
/*(async () => {
	const diffie = new Crypt.diffieHellman()
	const result = await diffie.init()
	console.log(result)
	const crypt = Crypt.encryptDataGCM(result.KeysA.private, '{"name":"Alice"}')
	console.log('Base64 Crypt:', crypt)
	const decrypt = Crypt.decryptDataGCM(result.KeysB.private, crypt)
	console.log(decrypt)
})()*/