//
//  PasswordStoreType.swift
//  passKit
//
//  Copyright © 2024 Bob Sun. All rights reserved.
//

import Foundation

/// Type of password store (pass with GPG, or passage with age)
public enum PasswordStoreType: Equatable {
    case pass      // Traditional pass with .gpg files
    case passage   // passage with .age files
    case unknown

    /// File extension for encrypted password files
    public var fileExtension: String {
        switch self {
        case .pass:
            return "gpg"
        case .passage:
            return "age"
        case .unknown:
            return ""
        }
    }

    /// Key/recipient marker filename
    public var recipientFileName: String {
        switch self {
        case .pass:
            return ".gpg-id"
        case .passage:
            return ".age-recipients"
        case .unknown:
            return ""
        }
    }

    /// Detect store type from directory contents
    public static func detect(at url: URL) -> PasswordStoreType {
        let fileManager = FileManager.default

        // Check for .gpg-id (pass)
        let gpgIdPath = url.appendingPathComponent(".gpg-id")
        if fileManager.fileExists(atPath: gpgIdPath.path) {
            return .pass
        }

        // Check for .age-recipients (passage)
        let ageRecipientsPath = url.appendingPathComponent(".age-recipients")
        if fileManager.fileExists(atPath: ageRecipientsPath.path) {
            return .passage
        }

        // Check for .age-identities (alternative passage marker)
        let ageIdentitiesPath = url.appendingPathComponent(".age-identities")
        if fileManager.fileExists(atPath: ageIdentitiesPath.path) {
            return .passage
        }

        return .unknown
    }
}
