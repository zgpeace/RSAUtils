/**
    RSA encryption and decryption
**/

import Foundation
import Security

class RSAUtils {

    static let applicationTag = "com.hsbc.publickey"
    static let keySizeInBits = 2048

    // generate RSA key pair
    static func generateRSAKeyPair() -> (SecKey?, SecKey?) {
        let publicKeyAttr: [NSObject: AnyObject] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: applicationTag
        ]
        let privateKeyAttr: [NSObject: AnyObject] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: applicationTag
        ]
        let keyPairAttr: [NSObject: AnyObject] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: keySizeInBits,
            kSecPublicKeyAttrs: publicKeyAttr,
            kSecPrivateKeyAttrs: privateKeyAttr
        ]
        var publicKey: SecKey?
        var privateKey: SecKey?
        let status = SecKeyGeneratePair(keyPairAttr, &publicKey, &privateKey)
        if status == errSecSuccess {
            return (publicKey, privateKey)
        } else {
            return (nil, nil)
        }
    }

    // get public key from keychain
    static func getPublicKey() -> SecKey? {
        let query: [NSObject: AnyObject] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag: kSecAttrApplicationTag,
            kSecReturnRef: true
        ]
        var key: AnyObject?
        let status = SecItemCopyMatching(query, &key)
        if status == errSecSuccess {
            return key as? SecKey
        } else {
            return nil
        }
    }

    // save public key to keychain
    static func savePublicKey(publicKey: SecKey) -> Bool {
        let query: [NSObject: AnyObject] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag: kSecAttrApplicationTag,
            kSecValueRef: publicKey
        ]
        let status = SecItemAdd(query, nil)
        return status == errSecSuccess
    }

    // encrypt data with public key
    static func encrypt(data: NSData, publicKey: SecKey) -> NSData? {
        let blockSize = SecKeyGetBlockSize(publicKey)
        let blockCount = data.length / blockSize + 1
        let buffer = UnsafeMutablePointer<UInt8>.alloc(blockSize * blockCount)
        var bufferOffset = 0
        var blockOffset = 0
        while blockOffset < data.length {
            let blockSize = min(blockSize, data.length - blockOffset)
            data.getBytes(buffer.advancedBy(bufferOffset), range: NSMakeRange(blockOffset, blockSize))
            let status = SecKeyEncrypt(publicKey, SecPadding.PKCS1, buffer.advancedBy(bufferOffset), blockSize, buffer.advancedBy(bufferOffset), &blockSize)
            if status != errSecSuccess {
                return nil
            }
            bufferOffset += blockSize
            blockOffset += blockSize
        }
        return NSData(bytes: buffer, length: bufferOffset)
    }

    // encrypt string with public key
    static func encrypt(string: String, publicKey: SecKey) -> NSData? {
        let data = string.dataUsingEncoding(NSUTF8StringEncoding)
        return encrypt(data!, publicKey: publicKey)
    }

    // encrypt string with private key
    static func encrypt(string: String, privateKey: SecKey) -> NSData? {
        let data = string.dataUsingEncoding(NSUTF8StringEncoding)
        return encrypt(data!, privateKey: privateKey)
    }

    // decrypt data with private key
    static func decrypt(data: NSData, privateKey: SecKey) -> NSData? {
        let blockSize = SecKeyGetBlockSize(privateKey)
        let blockCount = data.length / blockSize + 1
        let buffer = UnsafeMutablePointer<UInt8>.alloc(blockSize * blockCount)
        var bufferOffset = 0
        var blockOffset = 0
        while blockOffset < data.length {
            let blockSize = min(blockSize, data.length - blockOffset)
            data.getBytes(buffer.advancedBy(bufferOffset), range: NSMakeRange(blockOffset, blockSize))
            let status = SecKeyDecrypt(privateKey, SecPadding.PKCS1, buffer.advancedBy(bufferOffset), blockSize, buffer.advancedBy(bufferOffset), &blockSize)
            if status != errSecSuccess {
                return nil
            }
            bufferOffset += blockSize
            blockOffset += blockSize
        }
        return NSData(bytes: buffer, length: bufferOffset)
    }

    // sign data with private key
    static func sign(data: NSData, privateKey: SecKey) -> NSData? {
        let blockSize = SecKeyGetBlockSize(privateKey)
        let blockCount = data.length / blockSize + 1
        let buffer = UnsafeMutablePointer<UInt8>.alloc(blockSize * blockCount)
        var bufferOffset = 0
        var blockOffset = 0
        while blockOffset < data.length {
            let blockSize = min(blockSize, data.length - blockOffset)
            data.getBytes(buffer.advancedBy(bufferOffset), range: NSMakeRange(blockOffset, blockSize))
            let status = SecKeyRawSign(privateKey, SecPadding.PKCS1, buffer.advancedBy(bufferOffset), blockSize, buffer.advancedBy(bufferOffset), &blockSize)
            if status != errSecSuccess {
                return nil
            }
            bufferOffset += blockSize
            blockOffset += blockSize
        }
        return NSData(bytes: buffer, length: bufferOffset)
    }

    // validate signature with public key
    static func validateSignature(signature: NSData, data: NSData, publicKey: SecKey) -> Bool {
        let blockSize = SecKeyGetBlockSize(publicKey)
        let blockCount = data.length / blockSize + 1
        let buffer = UnsafeMutablePointer<UInt8>.alloc(blockSize * blockCount)
        var bufferOffset = 0
        var blockOffset = 0
        while blockOffset < data.length {
            let blockSize = min(blockSize, data.length - blockOffset)
            data.getBytes(buffer.advancedBy(bufferOffset), range: NSMakeRange(blockOffset, blockSize))
            let status = SecKeyRawVerify(publicKey, SecPadding.PKCS1, buffer.advancedBy(bufferOffset), blockSize, buffer.advancedBy(bufferOffset), &blockSize)
            if status != errSecSuccess {
                return false
            }
            bufferOffset += blockSize
            blockOffset += blockSize
        }
        return true
    }

}

// Test CASE for RSA
// let (publicKey, privateKey) = RSA.generateKeyPair(2048)
// RSA.savePublicKey(publicKey!)
// let publicKey2 = RSA.getPublicKey()
// let encryptedData = RSA.encrypt("Hello World", publicKey: publicKey2!)
// let decryptedData = RSA.decrypt(encryptedData!, privateKey: privateKey!)
// let signature = RSA.sign(decryptedData!, privateKey: privateKey!)
// RSA.validateSignature(signature!, data: decryptedData!, publicKey: publicKey2!)
