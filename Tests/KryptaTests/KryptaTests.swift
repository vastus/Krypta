import Testing
import XCTest

@testable import Krypta

let password = "Ride the wave."

let key = [Byte]([
    0x58, 0xc5, 0x75, 0x38, 0x9b, 0xc1, 0xf0, 0x70, 0xac, 0x86, 0x70, 0xf4, 0x25, 0xee, 0x14, 0x62,
    0x64, 0x67, 0x82, 0xdf, 0xe3, 0xb3, 0xc3, 0x31, 0x49, 0x26, 0x90, 0x3e, 0xe8, 0x06, 0x2e, 0x9c,
])

func mkUniqCryptDir() -> String {
    let fm = FileManager.default
    let path = "/tmp/krypta-test/\(UUID().uuidString)"

    print("path", path)
    try! fm.createDirectory(atPath: path, withIntermediateDirectories: true)

    return path
}

@Test
func encryptDecrypt() throws {
    let message = "testos"

    let relic = try encrypt(key: key, plain: [Byte](message.utf8))
    let plain = try decrypt(key: key, relic: relic)

    guard let actual = String(bytes: plain, encoding: .utf8) else {
        fatalError("failed to convert bytes to string")
    }

    #expect(message == actual)
}

@Test
func initialize() throws {
    let fm = FileManager.default
    let cryptPath = mkUniqCryptDir()

    defer { try! fm.removeItem(atPath: cryptPath) }
    try Krypta.initialize(cryptPath: cryptPath, password: password)

    let contents = try fm.contentsOfDirectory(atPath: cryptPath)

    #expect(contents.sorted() == [".krypta", "skeleton.key"])
}

@Test
func add() throws {
    let fm = FileManager.default
    let cryptPath = mkUniqCryptDir()

    defer { try! fm.removeItem(atPath: cryptPath) }
    try Krypta.initialize(cryptPath: cryptPath, password: password)

    let name = "yahoo.com"
    let secret = "You tryna AWOL"

    let krypta = try Krypta(cryptPath: cryptPath)
    try krypta.add(name: name, secret: secret)

    let itemURL = URL(filePath: cryptPath)
        .appendingPathComponent(name)
        .appendingPathExtension(itemExtension)

    var isDir = ObjCBool(false)
    let exists = fm.fileExists(atPath: itemURL.path, isDirectory: &isDir)

    #expect(!isDir.boolValue, "item path should not be a dir")
    #expect(exists, "item should exist")
}
