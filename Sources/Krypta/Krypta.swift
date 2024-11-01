import Foundation

import Copenssl

public typealias Byte = UInt8

let kSaltLen = 8
let kKeyLen = 32
let kIVMagic = "Initialization__"
let kIVLen = 16
let kNumIterations: Int32 = 100_000
let kBufSize = 1024
let kCipherBlockSize = 16

let keyFileName = "skeleton.key"
let kCryptFileName = ".krypta"

let itemExtension = "relic"

extension Data {
    func bytes() -> [Byte] {
        return [Byte](self)
    }
}

public enum KryptaError: Error {
    case noSuchRelic
}

public struct Relic {
    let ivMagic = [Byte](kIVMagic.utf8)
    let iv: [Byte]
    let cipher: [Byte]

    public init(iv: [Byte], cipher: [Byte]) {
        self.iv = iv
        self.cipher = cipher
    }

    public init(fromURL relicURL: URL) throws {
        let fh = try FileHandle(forReadingFrom: relicURL)

        // extract iv magic
        guard let readIVMagic = try fh.read(upToCount: kIVMagic.count) else {
            fatalError("failed to read IV magic")
        }

        // assert iv magic is correct
        guard readIVMagic == Data(kIVMagic.utf8) else {
            fatalError("failed to verify IV magic")
        }

        // extract iv
        guard let iv = try fh.read(upToCount: kIVLen) else {
            fatalError("failed to read IV")
        }

        // extract cipher
        guard let cipher = try fh.readToEnd() else {
            fatalError("failed to read cipher from file")
        }

        self.iv = iv.bytes()
        self.cipher = cipher.bytes()
    }

    public func bytes() -> [Byte] {
        return ivMagic + iv + cipher
    }
}

public struct Krypta: ~Copyable {
    private let cryptURL: URL
    private let cryptFileURL: URL
    private let keyURL: URL

    private let key: [Byte]

    public init(cryptPath: String) throws {
        let ctx = EVP_CIPHER_CTX_new()
        defer { EVP_CIPHER_CTX_free(ctx) }

        // save em as individual files to crypt path
        let fm = FileManager.default

        var isDir = ObjCBool(false)
        if fm.fileExists(atPath: cryptPath, isDirectory: &isDir) {
            if !isDir.boolValue {
                fatalError("Invalid crypt path. File exists and is not a directory.")
            }

            // TODO: check we have all necessary files
        // } else {
        //     throw KryptaError.missingCrypt
        }

        cryptURL = URL(fileURLWithPath: cryptPath)
        cryptFileURL = cryptURL.appendingPathComponent(kCryptFileName)
        keyURL = cryptURL.appendingPathComponent(keyFileName)

        let keyData = try! Data(contentsOf: keyURL)
        self.key = [Byte](keyData)
    }

    public static func initialize(cryptPath: String, password: String) throws {
        var buf = [Byte](repeating: 0, count: kBufSize)

        // generate salt
        guard RAND_bytes(&buf, Int32(kSaltLen)) == 1 else {
            fatalError("failed to generate salt")
        }

        let salt = buf[0..<kSaltLen]

        // generate key
        let (key, _) = try generateKeyAndIV(password: password, salt: salt)

        // save em as individual files to crypt path
        let fm = FileManager.default

        var isDir = ObjCBool(false)
        if fm.fileExists(atPath: cryptPath, isDirectory: &isDir) {
            if !isDir.boolValue {
                fatalError("Invalid crypt path. File exists.")
            }

            // ignore if dir is empty
            let contents = try fm.contentsOfDirectory(atPath: cryptPath)

            // TODO: have we already initialized?
            if !contents.isEmpty {
                fatalError("Crypt path directory already exists: \(cryptPath).")
            }
        } else {
            try! fm.createDirectory(atPath: cryptPath, withIntermediateDirectories: false)
        }

        let cryptURL = URL(fileURLWithPath: cryptPath)
        let cryptFileURL = cryptURL.appendingPathComponent(kCryptFileName)
        let keyURL = cryptURL.appendingPathComponent(keyFileName)

        fm.createFile(atPath: cryptFileURL.path, contents: nil)

        try Data(key).write(to: keyURL)
    }

    public func add(name: String) throws {
        print("Type secret for '\(name)': ", terminator: "")
        guard let secret = readLine(strippingNewline: true) else {
            fatalError("failed to get secret")
        }

        print("Re-enter secret for '\(name)': ", terminator: "")
        guard let confirmation = readLine(strippingNewline: true) else {
            fatalError("failed to get secret confirmation")
        }

        if secret != confirmation {
            fatalError("Secrets don't match. Abort.")
        }

        try add(name: name, secret: secret)
    }

    public func add(name: String, secret: String) throws {
        // TODO: sanitize name before writing file
        let itemPathURL = cryptURL
            .appendingPathComponent(name)
            .appendingPathExtension(itemExtension)  // dot (.) is implicit

        // encrypt the password
        let relic = try encrypt(key: key, plain: [Byte](secret.utf8))

        // write it to disk
        try Data(relic.bytes()).write(to: itemPathURL)
    }

    public func retrieve(name: String) throws -> String {
        let fm = FileManager.default

        // build file path URL
        let itemURL = cryptURL
            .appendingPathComponent(name)
            .appendingPathExtension(itemExtension)

        // exit if not found
        var isDir = ObjCBool(false)
        if !fm.fileExists(atPath: itemURL.path, isDirectory: &isDir) {
            fatalError("TODO: no such password item: \(itemURL.path)")
        }

        if isDir.boolValue {
            fatalError("TODO: file path is dir, aborting")
        }

        let relic = try Relic(fromURL: itemURL)

        let decrypted = try decrypt(key: key, relic: relic)

        guard let plain = String(bytes: decrypted, encoding: .utf8) else {
            fatalError("failed to convert bytes to string")
        }

        return plain
    }

    public func list() throws -> [String] {
        let fm = FileManager.default
        let items = try fm.contentsOfDirectory(atPath: cryptURL.path)
        let suffix = "." + itemExtension

        return items
            .filter { $0.hasSuffix(suffix) }
            .map { $0.dropLast(suffix.count) }
            .map { String($0) }
    }

    public func remove(name: String) throws -> Result<Void, Error> {
        // TODO: sanitize name before writing file
        let itemURL = cryptURL
            .appendingPathComponent(name)
            .appendingPathExtension(itemExtension)

        let fm = FileManager.default

        if !fm.fileExists(atPath: itemURL.path) {
            return .failure(KryptaError.noSuchRelic)
        }

        try fm.removeItem(at: itemURL)
        return .success(())
    }
}

func generateKeyAndIV(password: String, salt: ArraySlice<Byte>) throws -> ([Byte], [Byte]) {
    let digest = EVP_sha256()
    var keyAndIV = [Byte](repeating: 0, count: kKeyLen+kIVLen)
    let saltPtr = salt.withUnsafeBufferPointer { $0.baseAddress }

    PKCS5_PBKDF2_HMAC(
        password, Int32(password.count),
        saltPtr, Int32(kSaltLen),
        kNumIterations, digest,
        Int32(kKeyLen+kIVLen), &keyAndIV
    )

    let key = Array<Byte>(keyAndIV[0..<kKeyLen])
    let iv = Array<Byte>(keyAndIV[kKeyLen...])

    assert(key.count == kKeyLen)
    assert(iv.count == kIVLen)

    return (key, iv)
}

public func encrypt(key: [Byte], plain: [Byte]) throws -> Relic {
    let ctx = EVP_CIPHER_CTX_new()
    defer { EVP_CIPHER_CTX_free(ctx) }

    var nbytes = Int32(-1)
    var outBuf = [Byte](repeating: 0, count: plain.count + kCipherBlockSize)
    var encrypted = [Byte]()

    var padding = UInt32(1)
    let params: [OSSL_PARAM] = [
        OSSL_PARAM_construct_uint("padding", &padding),
        OSSL_PARAM_construct_end()
    ]

    // generate new IV for this relic
    var iv = [Byte](repeating: 0, count: kIVLen)
    guard RAND_bytes(&iv, Int32(kIVLen)) == 1 else {
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
