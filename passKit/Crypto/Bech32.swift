//
//  Bech32.swift
//  passKit
//

import Foundation

// swiftlint:disable identifier_name

/// Bech32/Bech32m encoding for age recipient strings
public enum Bech32 {
    public enum Error: Swift.Error {
        case invalidCharacter
        case invalidChecksum
        case invalidLength
        case invalidHRP
    }

    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
    private static let charsetMap: [Character: UInt8] = {
        var map: [Character: UInt8] = [:]
        for (i, c) in charset.enumerated() {
            map[c] = UInt8(i)
        }
        return map
    }()

    public static func encode(hrp: String, data: Data) throws -> String {
        let values = convertTo5Bit(data: data)
        let checksum = createChecksum(hrp: hrp, values: values)
        let combined = values + checksum

        var result = hrp + "1"
        for v in combined {
            result.append(charset[Int(v)])
        }
        return result
    }

    public static func decode(_ string: String) throws -> (hrp: String, data: Data) {
        let lower = string.lowercased()
        guard let separatorIndex = lower.lastIndex(of: "1") else {
            throw Error.invalidHRP
        }

        let hrp = String(lower[..<separatorIndex])
        let dataPartStart = lower.index(after: separatorIndex)
        let dataPart = String(lower[dataPartStart...])

        var values: [UInt8] = []
        for c in dataPart {
            guard let v = charsetMap[c] else {
                throw Error.invalidCharacter
            }
            values.append(v)
        }

        guard verifyChecksum(hrp: hrp, values: values) else {
            throw Error.invalidChecksum
        }

        let dataValues = Array(values.dropLast(6))
        let data = try convertFrom5Bit(values: dataValues)
        return (hrp, data)
    }

    private static func convertTo5Bit(data: Data) -> [UInt8] {
        var result: [UInt8] = []
        var acc: UInt32 = 0
        var bits: UInt32 = 0

        for byte in data {
            acc = (acc << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                result.append(UInt8((acc >> bits) & 0x1F))
            }
        }
        if bits > 0 {
            result.append(UInt8((acc << (5 - bits)) & 0x1F))
        }
        return result
    }

    private static func convertFrom5Bit(values: [UInt8]) throws -> Data {
        var result: [UInt8] = []
        var acc: UInt32 = 0
        var bits: UInt32 = 0

        for v in values {
            acc = (acc << 5) | UInt32(v)
            bits += 5
            while bits >= 8 {
                bits -= 8
                result.append(UInt8((acc >> bits) & 0xFF))
            }
        }
        return Data(result)
    }

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        let gen: [UInt32] = [0x3B6A_57B2, 0x2650_8E6D, 0x1EA1_19FA, 0x3D42_33DD, 0x2A14_62B3]
        var chk: UInt32 = 1
        for v in values {
            let top = chk >> 25
            chk = ((chk & 0x01FF_FFFF) << 5) ^ UInt32(v)
            for i in 0 ..< 5 where ((top >> i) & 1) == 1 {
                chk ^= gen[i]
            }
        }
        return chk
    }

    private static func hrpExpand(_ hrp: String) -> [UInt8] {
        var result: [UInt8] = []
        for c in hrp {
            result.append(UInt8(c.asciiValue! >> 5))
        }
        result.append(0)
        for c in hrp {
            result.append(UInt8(c.asciiValue! & 31))
        }
        return result
    }

    private static func createChecksum(hrp: String, values: [UInt8]) -> [UInt8] {
        let polymodInput = hrpExpand(hrp) + values + [0, 0, 0, 0, 0, 0]
        let polymodResult = polymod(polymodInput) ^ 1
        var result: [UInt8] = []
        for i in 0 ..< 6 {
            result.append(UInt8((polymodResult >> (5 * (5 - i))) & 31))
        }
        return result
    }

    private static func verifyChecksum(hrp: String, values: [UInt8]) -> Bool {
        polymod(hrpExpand(hrp) + values) == 1
    }
}
