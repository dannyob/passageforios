//
//  Bech32Test.swift
//  passKitTests
//

import XCTest
@testable import passKit

final class Bech32Test: XCTestCase {

    func testEncodeDecodeRoundTrip() throws {
        let testData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let encoded = try Bech32.encode(hrp: "age1tag", data: testData)

        XCTAssertTrue(encoded.hasPrefix("age1tag1"))

        let (hrp, decoded) = try Bech32.decode(encoded)
        XCTAssertEqual(hrp, "age1tag")
        XCTAssertEqual(decoded, testData)
    }

    func testKnownVector() throws {
        // Test vector from BIP-173
        let data = Data([0x00, 0x14] + Array(repeating: UInt8(0x00), count: 20))
        let encoded = try Bech32.encode(hrp: "bc", data: data)
        XCTAssertEqual(encoded, "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs")
    }

    func testInvalidChecksum() {
        XCTAssertThrowsError(try Bech32.decode("age1tag1qqqqqqqqqqqqqqqinvalid"))
    }
}
