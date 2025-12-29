//
//  PasswordStoreTypeTest.swift
//  passKitTests
//
//  Copyright © 2024 Bob Sun. All rights reserved.
//

import XCTest

@testable import passKit

final class PasswordStoreTypeTest: XCTestCase {
    var tempDir: URL!

    override func setUp() {
        super.setUp()
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempDir)
        super.tearDown()
    }

    func testDetectsPassStore() throws {
        // Create .gpg-id file
        let gpgIdFile = tempDir.appendingPathComponent(".gpg-id")
        try "ABCD1234".write(to: gpgIdFile, atomically: true, encoding: .utf8)

        let storeType = PasswordStoreType.detect(at: tempDir)
        XCTAssertEqual(storeType, .pass)
    }

    func testDetectsPassageStore() throws {
        // Create .age-recipients file
        let ageRecipientsFile = tempDir.appendingPathComponent(".age-recipients")
        try "age1abc123...".write(to: ageRecipientsFile, atomically: true, encoding: .utf8)

        let storeType = PasswordStoreType.detect(at: tempDir)
        XCTAssertEqual(storeType, .passage)
    }

    func testDetectsPassageStoreWithIdentitiesFile() throws {
        // Some passage setups use .age-identities
        let ageIdentitiesFile = tempDir.appendingPathComponent(".age-identities")
        try "AGE-SECRET-KEY-1...".write(to: ageIdentitiesFile, atomically: true, encoding: .utf8)

        let storeType = PasswordStoreType.detect(at: tempDir)
        XCTAssertEqual(storeType, .passage)
    }

    func testUnknownWhenNoMarkerFiles() {
        let storeType = PasswordStoreType.detect(at: tempDir)
        XCTAssertEqual(storeType, .unknown)
    }

    func testFileExtensionForPass() {
        XCTAssertEqual(PasswordStoreType.pass.fileExtension, "gpg")
    }

    func testFileExtensionForPassage() {
        XCTAssertEqual(PasswordStoreType.passage.fileExtension, "age")
    }
}
