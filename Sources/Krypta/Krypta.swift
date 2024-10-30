import Foundation

import Copenssl

public typealias Byte = UInt8

let saltMagic = "Salted__"
let saltLen = 8
let keyLen = 32
let kIVMagic = "Initialization__"
let ivLen = 16
let numIterations: Int32 = 10_000
let bufSize = 1024
let cipherBlockSize = 16

let saltFileName = "salt"
let keyFileName = "key"
let ivFileName = "iv"

let itemExtension = "relic"

extension Data {
    func bytes() -> [Byte] {
        return [Byte](self)
    }
}

enum KryptaError: Error {
    case badIVMagic
}

public struct Relic {
    let ivMagic = [Byte](kIVMagic.utf8)
    let iv: [Byte]
    let cipher: [Byte]
}

func generateKeyAndIV(password: String, salt: ArraySlice<Byte>) throws -> ([Byte], [Byte]) {
    let digest = EVP_sha256()
    var keyAndIV = [Byte](repeating: 0, count: keyLen+ivLen)
    let saltPtr = salt.withUnsafeBufferPointer { $0.baseAddress }

    PKCS5_PBKDF2_HMAC(
        password, Int32(password.count),
        saltPtr, Int32(saltLen),
        numIterations, digest,
        Int32(keyLen+ivLen), &keyAndIV
    )

    let key = Array<Byte>(keyAndIV[0..<keyLen])
    let iv = Array<Byte>(keyAndIV[keyLen...])

    assert(key.count == keyLen)
    assert(iv.count == ivLen)

    return (key, iv)
}

public func encrypt(key: [Byte], plain: [Byte]) throws -> Relic {
    let ctx = EVP_CIPHER_CTX_new()
    defer { EVP_CIPHER_CTX_free(ctx) }

    var nbytes = Int32(-1)
    var outBuf = [Byte](repeating: 0, count: plain.count + cipherBlockSize)
    var encrypted = [Byte]()

    var padding = UInt32(1)
    let params: [OSSL_PARAM] = [
        OSSL_PARAM_construct_uint("padding", &padding),
        OSSL_PARAM_construct_end()
    ]

    // generate new IV for this relic
    var iv = [Byte](repeating: 0, count: ivLen)
    guard RAND_bytes(&iv, Int32(ivLen)) == 1 else {
        fatalError("failed to generate IV")
    }

    // encrypted.append(contentsOf: kIVMagic.utf8)
    // encrypted.append(contentsOf: iv)

    // init encrypt
    guard EVP_EncryptInit_ex2(ctx, EVP_aes_256_cbc(), key, iv, params) == 1 else {
        fatalError("failed to init encryption")
    }

    // encrypt update
    guard EVP_EncryptUpdate(ctx, &outBuf, &nbytes, plain, Int32(plain.count)) == 1 else {
        ERR_print_errors_fp(stderr)
        fatalError("failed to encrypt update")
    }

    guard nbytes <= outBuf.count else {
        fatalError("critial error: failed to encrypt update bytes")
    }

    encrypted.append(contentsOf: outBuf[0..<Int(nbytes)])

    // encrypt final
    guard EVP_EncryptFinal(ctx, &outBuf, &nbytes) == 1 else {
        fatalError("failed to encrypt final")
    }

    guard nbytes <= outBuf.count else {
        fatalError("critial error: failed to encrypt final bytes")
    }

    encrypted.append(contentsOf: outBuf[0..<Int(nbytes)])

    let relic = Relic(iv: iv, cipher: encrypted)
    return relic
}

public func decrypt(key: [Byte], relic: Relic) throws -> [Byte] {
    return try decrypt(key: key, iv: relic.iv, cipher: relic.cipher)
}

public func decrypt(key: [Byte], iv: [Byte], cipher: [Byte]) throws -> [Byte] {
    let ctx = EVP_CIPHER_CTX_new()
    defer { EVP_CIPHER_CTX_free(ctx) }

    let cipherType = EVP_aes_256_cbc()

    var padding = UInt32(1)
    let params: [OSSL_PARAM] = [
        OSSL_PARAM_construct_uint("padding", &padding),
        OSSL_PARAM_construct_end()
     ]

    // init
    guard EVP_DecryptInit_ex2( ctx, cipherType, key, iv, params) == 1 else {
        fatalError("failed to encrypt init")
    }

    var buf = [Byte](repeating: 0, count: cipher.count)
    var plain = [Byte]()
    var nbytes = Int32(0)

    // decrypt update
    guard EVP_DecryptUpdate(ctx, &buf, &nbytes, cipher, Int32(cipher.count)) == 1 else {
        ERR_print_errors_fp(stderr)
        fatalError("failed to decrypt update")
    }

    guard nbytes <= buf.count else {
        fatalError("buffer not big enough for decryption")
    }

    plain.append(contentsOf: buf[0..<Int(nbytes)])

    // decrypt final
    guard EVP_DecryptFinal(ctx, &buf, &nbytes) == 1 else {
        fatalError("failed to decrypt final")
    }

    plain.append(contentsOf: buf[0..<Int(nbytes)])

    return plain
}
