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

        // Fallback: check for .age files (passage without .age-recipients)
        // This handles passage stores where user encrypts only to their own identity
        if hasAgeFiles(at: url) {
            return .passage
        }

        // Fallback: check for .gpg files (pass without .gpg-id)
        if hasGpgFiles(at: url) {
            return .pass
        }

        return .unknown
    }

    /// Check if directory contains any .age files (recursively, limited depth)
    private static func hasAgeFiles(at url: URL) -> Bool {
        hasFiles(withExtension: "age", at: url)
    }

    /// Check if directory contains any .gpg files (recursively, limited depth)
    private static func hasGpgFiles(at url: URL) -> Bool {
        hasFiles(withExtension: "gpg", at: url)
    }

    /// Check if directory contains files with given extension (shallow check for performance)
    private static func hasFiles(withExtension ext: String, at url: URL) -> Bool {
        let fileManager = FileManager.default
        guard let enumerator = fileManager.enumerator(
            at: url,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else {
            return false
        }

        // Check first few levels only for performance
        var depth = 0
        let maxDepth = 3
        var checkedFiles = 0
        let maxFiles = 100

        while let fileURL = enumerator.nextObject() as? URL {
            // Limit search depth and file count for performance
            depth = enumerator.level
            if depth > maxDepth {
                enumerator.skipDescendants()
                continue
            }

            checkedFiles += 1
            if checkedFiles > maxFiles {
                break
            }

            if fileURL.pathExtension.lowercased() == ext {
                return true
            }
        }

        return false
    }
}
