//
//  PasswordStore.swift
//  passKit
//
//  Created by Mingshen Sun on 19/1/2017.
//  Copyright © 2017 Bob Sun. All rights reserved.
//

import CoreData
import Foundation
import KeychainAccess
import ObjectiveGit
import SwiftyUserDefaults
import UIKit

public class PasswordStore {
    public static let shared = PasswordStore()
    private static let dateFormatter: DateFormatter = {
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .short
        dateFormatter.timeStyle = .short
        return dateFormatter
    }()

    public var storeURL: URL

    public var gitRepository: GitRepository?

    public var gitSignatureForNow: GTSignature? {
        let gitSignatureName = Defaults.gitSignatureName ?? Globals.gitSignatureDefaultName
        let gitSignatureEmail = Defaults.gitSignatureEmail ?? Globals.gitSignatureDefaultEmail
        return GTSignature(name: gitSignatureName, email: gitSignatureEmail, time: Date())
    }

    public var gitPassword: String? {
        get {
            AppKeychain.shared.get(for: Globals.gitPassword)
        }
        set {
            AppKeychain.shared.add(string: newValue, for: Globals.gitPassword)
        }
    }

    public var gitSSHPrivateKeyPassphrase: String? {
        get {
            AppKeychain.shared.get(for: Globals.gitSSHPrivateKeyPassphrase)
        }
        set {
            AppKeychain.shared.add(string: newValue, for: Globals.gitSSHPrivateKeyPassphrase)
        }
    }

    private let fileManager = FileManager.default
    private let notificationCenter = NotificationCenter.default
    private lazy var context: NSManagedObjectContext = PersistenceController.shared.viewContext()

    public var numberOfPasswords: Int {
        PasswordEntity.totalNumber(in: context)
    }

    /// Whether the store is ready to perform crypto operations (has required keys/identities)
    public var isPreparedForCrypto: Bool {
        CryptoAgent(storeURL: storeURL).isPrepared
    }

    public var sizeOfRepositoryByteCount: UInt64 {
        (try? fileManager.allocatedSizeOfDirectoryAtURL(directoryURL: storeURL)) ?? 0
    }

    public var numberOfLocalCommits: Int {
        (try? getLocalCommits()).map(\.count) ?? 0
    }

    public var lastSyncedTime: Date? {
        Defaults.lastSyncedTime
    }

    public var lastSyncedTimeString: String {
        guard let date = lastSyncedTime else {
            return "SyncAgain?".localize()
        }
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }

    public var numberOfCommits: Int? {
        gitRepository?.numberOfCommits()
    }

    init(url: URL = Globals.repositoryURL) {
        self.storeURL = url

        // Migration
        importExistingKeysIntoKeychain()

        do {
            if fileManager.fileExists(atPath: storeURL.path) {
                try self.gitRepository = GitRepository(with: storeURL)
            }
        } catch {
            print(error)
        }
    }

    private func importExistingKeysIntoKeychain() {
        // App Store update: v0.5.1 -> v0.6.0
        try? KeyFileManager(keyType: PGPKey.PUBLIC, keyPath: Globals.pgpPublicKeyPath).importKeyFromFileSharing()
        try? KeyFileManager(keyType: PGPKey.PRIVATE, keyPath: Globals.pgpPrivateKeyPath).importKeyFromFileSharing()
        try? KeyFileManager(keyType: SSHKey.PRIVATE, keyPath: Globals.gitSSHPrivateKeyPath).importKeyFromFileSharing()
        Defaults.remove(\.pgpPublicKeyArmor)
        Defaults.remove(\.pgpPrivateKeyArmor)
        Defaults.remove(\.gitSSHPrivateKeyArmor)
    }

    public func repositoryExists() -> Bool {
        fileManager.fileExists(atPath: Globals.repositoryURL.path)
    }

    public func cloneRepository(
        remoteRepoURL: URL,
        branchName: String,
        options: CloneOptions = [:],
        transferProgressBlock: @escaping TransferProgressHandler = { _, _ in },
        checkoutProgressBlock: @escaping CheckoutProgressHandler = { _, _, _ in }
    ) throws {
        try? fileManager.removeItem(at: storeURL)
        gitPassword = nil
        gitSSHPrivateKeyPassphrase = nil
        do {
            gitRepository = try GitRepository(from: remoteRepoURL, to: storeURL, branchName: branchName, options: options, transferProgressBlock: transferProgressBlock, checkoutProgressBlock: checkoutProgressBlock)
        } catch {
            Defaults.lastSyncedTime = nil
            DispatchQueue.main.async {
                self.deleteCoreData()
                self.notificationCenter.post(name: .passwordStoreUpdated, object: nil)
            }
            throw (error)
        }
        Defaults.lastSyncedTime = Date()
        DispatchQueue.main.async {
            self.deleteCoreData()
            self.initPasswordEntityCoreData()
            self.notificationCenter.post(name: .passwordStoreUpdated, object: nil)
        }
    }

    public func pullRepository(
        options: PullOptions,
        progressBlock: @escaping TransferProgressHandler = { _, _ in }
    ) throws {
        guard let gitRepository else {
            throw AppError.repositoryNotSet
        }
        try gitRepository.pull(options: options, transferProgressBlock: progressBlock)
        Defaults.lastSyncedTime = Date()
        setAllSynced()
        DispatchQueue.main.async {
            self.deleteCoreData()
            self.initPasswordEntityCoreData()
            self.notificationCenter.post(name: .passwordStoreUpdated, object: nil)
        }
    }

    private func initPasswordEntityCoreData() {
        PasswordEntity.initPasswordEntityCoreData(url: storeURL, in: context)
        saveUpdatedContext()
    }

    public func getRecentCommits(count: Int) throws -> [GTCommit] {
        guard let gitRepository else {
            throw AppError.repositoryNotSet
        }
        return try gitRepository.getRecentCommits(count: count)
    }

    public func fetchPasswordEntityCoreData(parent: PasswordEntity?) -> [PasswordEntity] {
        PasswordEntity.fetch(by: parent, in: context)
    }

    public func fetchPasswordEntityCoreData(withDir _: Bool) -> [PasswordEntity] {
        PasswordEntity.fetchAllPassword(in: context)
    }

    public func fetchUnsyncedPasswords() -> [PasswordEntity] {
        PasswordEntity.fetchUnsynced(in: context)
    }

    public func fetchPasswordEntity(with path: String) -> PasswordEntity? {
        PasswordEntity.fetch(by: path, in: context)
    }

    public func setAllSynced() {
        _ = PasswordEntity.updateAllToSynced(in: context)
        saveUpdatedContext()
    }

    public func getLatestUpdateInfo(path: String) -> String {
        guard let gitRepository else {
            return "Unknown".localize()
        }
        guard let lastCommitDate = try? gitRepository.lastCommitDate(path: path) else {
            return "Unknown".localize()
        }
        if Date().timeIntervalSince(lastCommitDate) <= 60 {
            return "JustNow".localize()
        }
        return Self.dateFormatter.string(from: lastCommitDate)
    }

    private func deleteDirectoryTree(at url: URL) throws {
        var tempURL = url.deletingLastPathComponent()
        while try fileManager.contentsOfDirectory(atPath: tempURL.path).isEmpty {
            try fileManager.removeItem(at: tempURL)
            tempURL.deleteLastPathComponent()
        }
    }

    private func createDirectoryTree(at url: URL) throws {
        let tempURL = url.deletingLastPathComponent()
        try fileManager.createDirectory(at: tempURL, withIntermediateDirectories: true)
    }

    public func pushRepository(
        options: PushOptions,
        transferProgressBlock: @escaping PushProgressHandler = { _, _, _, _ in }
    ) throws {
        guard let gitRepository else {
            throw AppError.repositoryNotSet
        }
        try gitRepository.push(options: options, transferProgressBlock: transferProgressBlock)
    }

    private func addPasswordEntities(password: Password) throws -> PasswordEntity? {
        guard !PasswordEntity.exists(password: password, in: context) else {
            throw AppError.passwordDuplicated
        }

        var paths: [String] = []
        var path = password.path
        while !path.isEmpty {
            paths.append(path)
            path = (path as NSString).deletingLastPathComponent
        }

        var parentPasswordEntity: PasswordEntity?
        for (index, path) in paths.reversed().enumerated() {
            if index == paths.count - 1 {
                let passwordEntity = PasswordEntity.insert(name: password.name, path: path, isDir: false, into: context)
                passwordEntity.parent = parentPasswordEntity
                parentPasswordEntity = passwordEntity
            } else {
                if let passwordEntity = PasswordEntity.fetch(by: path, isDir: true, in: context) {
                    passwordEntity.isSynced = false
                    parentPasswordEntity = passwordEntity
                } else {
                    let name = (path as NSString).lastPathComponent
                    let passwordEntity = PasswordEntity.insert(name: name, path: path, isDir: true, into: context)
                    passwordEntity.parent = parentPasswordEntity
                    parentPasswordEntity = passwordEntity
                }
            }
        }
        saveUpdatedContext()
        return parentPasswordEntity
    }

    public func add(password: Password, keyID: String? = nil) throws -> PasswordEntity? {
        let saveURL = password.fileURL(in: storeURL)
        try createDirectoryTree(at: saveURL)
        try encrypt(password: password, keyID: keyID).write(to: saveURL)
        try gitAdd(path: password.path)
        try gitCommit(message: "AddPassword.".localize(password.path))
        let newPasswordEntity = try addPasswordEntities(password: password)
        notificationCenter.post(name: .passwordStoreUpdated, object: nil)
        return newPasswordEntity
    }

    public func delete(passwordEntity: PasswordEntity) throws {
        let deletedFileURL = passwordEntity.fileURL(in: storeURL)
        let deletedFilePath = passwordEntity.path
        try gitRm(path: passwordEntity.path)
        try deletePasswordEntities(passwordEntity: passwordEntity)
        try deleteDirectoryTree(at: deletedFileURL)
        try gitCommit(message: "RemovePassword.".localize(deletedFilePath))
        notificationCenter.post(name: .passwordStoreUpdated, object: nil)
    }

    public func edit(passwordEntity: PasswordEntity, password: Password, keyID: String? = nil) throws -> PasswordEntity? {
        var newPasswordEntity: PasswordEntity? = passwordEntity
        let url = passwordEntity.fileURL(in: storeURL)

        if password.changed & PasswordChange.content.rawValue != 0 {
            try encrypt(password: password, keyID: keyID).write(to: url)
            try gitAdd(path: password.path)
            try gitCommit(message: "EditPassword.".localize(passwordEntity.path))
            newPasswordEntity = passwordEntity
            newPasswordEntity?.isSynced = false
        }

        if password.changed & PasswordChange.path.rawValue != 0 {
            let deletedFileURL = url
            // add
            let newFileURL = password.fileURL(in: storeURL)
            try createDirectoryTree(at: newFileURL)
            newPasswordEntity = try addPasswordEntities(password: password)

            // mv
            try gitMv(from: passwordEntity.path, to: password.path)

            // delete
            try deleteDirectoryTree(at: deletedFileURL)
            let deletedFilePath = passwordEntity.path
            try deletePasswordEntities(passwordEntity: passwordEntity)
            try gitCommit(message: "RenamePassword.".localize(deletedFilePath, password.path))
        }
        saveUpdatedContext()
        notificationCenter.post(name: .passwordStoreUpdated, object: nil)
        return newPasswordEntity
    }

    private func deletePasswordEntities(passwordEntity: PasswordEntity) throws {
        PasswordEntity.deleteRecursively(entity: passwordEntity, in: context)
        saveUpdatedContext()
    }

    public func saveUpdatedContext() {
        PersistenceController.shared.save()
    }

    public func deleteCoreData() {
        // Core Data viewContext must be accessed from main thread
        if Thread.isMainThread {
            PasswordEntity.deleteAll(in: context)
            PersistenceController.shared.save()
        } else {
            DispatchQueue.main.sync {
                PasswordEntity.deleteAll(in: context)
                PersistenceController.shared.save()
            }
        }
    }

    public func eraseStoreData() {
        // Delete files.
        try? fileManager.removeItem(at: storeURL)

        // Delete core data.
        deleteCoreData()

        // Clean up variables inside PasswordStore.
        gitRepository = nil

        // Broadcast.
        notificationCenter.post(name: .passwordStoreUpdated, object: nil)
        notificationCenter.post(name: .passwordStoreErased, object: nil)
    }

    public func erase() {
        eraseStoreData()

        // Delete PGP key, SSH key and other secrets from the keychain.
        AppKeychain.shared.removeAllContent()

        // Delete default settings.
        Defaults.removeAll()

        // Delete cache explicitly.
        PasscodeLock.shared.delete()
        PGPAgent.shared.uninitKeys()
    }

    // return the number of discarded commits
    public func reset() throws -> Int {
        guard let gitRepository else {
            throw AppError.repositoryNotSet
        }
        let localCommitsCount = try getLocalCommits().count
        try gitRepository.reset()
        setAllSynced()
        deleteCoreData()
        initPasswordEntityCoreData()

        notificationCenter.post(name: .passwordStoreUpdated, object: nil)
        notificationCenter.post(name: .passwordStoreChangeDiscarded, object: nil)
        return localCommitsCount
    }

    private func getLocalCommits() throws -> [GTCommit] {
        guard let gitRepository else {
            throw AppError.repositoryNotSet
        }
        return try gitRepository.getLocalCommits()
    }

    public func decrypt(passwordEntity: PasswordEntity, keyID: String? = nil, requestPGPKeyPassphrase: @escaping (String) -> String) throws -> Password {
        let url = passwordEntity.fileURL(in: storeURL)
        let encryptedData = try Data(contentsOf: url)

        let cryptoAgent = CryptoAgent(storeURL: storeURL)
        let data: Data = try {
            switch cryptoAgent.storeType {
            case .pass:
                // Use keyID logic for PGP stores
                if Defaults.isEnableGPGIDOn {
                    let resolvedKeyID = keyID ?? findGPGID(from: url)
                    return try cryptoAgent.decrypt(encryptedData: encryptedData, keyID: resolvedKeyID, requestPassphrase: requestPGPKeyPassphrase)
                }
                return try cryptoAgent.decrypt(encryptedData: encryptedData, requestPassphrase: requestPGPKeyPassphrase)

            case .passage, .unknown:
                // Age stores don't use keyID for decryption
                return try cryptoAgent.decrypt(encryptedData: encryptedData, requestPassphrase: requestPGPKeyPassphrase)
            }
        }()
        let plainText = String(data: data, encoding: .utf8) ?? ""
        return Password(name: passwordEntity.name, path: passwordEntity.path, plainText: plainText)
    }

    public func decrypt(path: String, keyID: String? = nil, requestPGPKeyPassphrase: @escaping (String) -> String) throws -> Password {
        guard let passwordEntity = fetchPasswordEntity(with: path) else {
            throw AppError.decryption
        }
        if Defaults.isEnableGPGIDOn {
            return try decrypt(passwordEntity: passwordEntity, keyID: keyID, requestPGPKeyPassphrase: requestPGPKeyPassphrase)
        }
        return try decrypt(passwordEntity: passwordEntity, requestPGPKeyPassphrase: requestPGPKeyPassphrase)
    }

    public func encrypt(password: Password, keyID: String? = nil) throws -> Data {
        let encryptedDataPath = password.fileURL(in: storeURL)

        let cryptoAgent = CryptoAgent(storeURL: storeURL)
        switch cryptoAgent.storeType {
        case .pass:
            // Use keyID logic for PGP stores
            let resolvedKeyID = keyID ?? findGPGID(from: encryptedDataPath)
            if Defaults.isEnableGPGIDOn {
                return try cryptoAgent.encrypt(plainData: password.plainData, keyID: resolvedKeyID)
            }
            return try cryptoAgent.encrypt(plainData: password.plainData)

        case .passage, .unknown:
            // Age stores use recipients from .age-recipients file
            return try cryptoAgent.encrypt(plainData: password.plainData)
        }
    }

    public func removeGitSSHKeys() {
        try? fileManager.removeItem(atPath: Globals.gitSSHPrivateKeyPath)
        Defaults.remove(\.gitSSHKeySource)
        Defaults.remove(\.gitSSHPrivateKeyArmor)
        Defaults.remove(\.gitSSHPrivateKeyURL)
        AppKeychain.shared.removeContent(for: SSHKey.PRIVATE.getKeychainKey())
        gitSSHPrivateKeyPassphrase = nil
    }
}

extension PasswordStore {
    private func gitAdd(path: String) throws {
        guard let gitRepository else {
            throw AppError.repositoryNotSet
        }
        try gitRepository.add(path: path)
    }

    private func gitRm(path: String) throws {
        guard let gitRepository else {
            throw AppError.repositoryNotSet
        }
        try gitRepository.rm(path: path)
    }

    private func gitMv(from: String, to: String) throws {
        guard let gitRepository else {
            throw AppError.repositoryNotSet
        }
        try gitRepository.mv(from: from, to: to)
    }

    @discardableResult
    private func gitCommit(message: String) throws -> GTCommit {
        guard let gitRepository, let gitSignatureForNow else {
            throw AppError.repositoryNotSet
        }
        return try gitRepository.commit(signature: gitSignatureForNow, message: message)
    }
}

func findGPGID(from url: URL) -> String {
    var path = url
    while !FileManager.default.fileExists(atPath: path.appendingPathComponent(".gpg-id").path),
          path.path != "file:///" {
        path = path.deletingLastPathComponent()
    }
    path = path.appendingPathComponent(".gpg-id")

    return (try? String(contentsOf: path))?.trimmed ?? ""
}

func findAgeRecipients(from url: URL) -> String {
    var path = url
    while !FileManager.default.fileExists(atPath: path.appendingPathComponent(".age-recipients").path),
          path.path != "file:///" {
        path = path.deletingLastPathComponent()
    }
    path = path.appendingPathComponent(".age-recipients")

    return (try? String(contentsOf: path))?.trimmed ?? ""
}

// MARK: - Trust Verification

public extension PasswordStore {
    /// Result of trust verification after pull
    enum TrustVerificationResult {
        /// Verification passed (or not applicable for non-passage stores)
        case verified
        /// Trust not yet initialized - UI should prompt for TOFU
        case trustNotInitialized
        /// Verification found issues - UI should display them
        case issues([TrustVerificationIssue])
    }

    /// Verify trust state after a pull operation.
    ///
    /// For passage stores, this verifies that any commits modifying `.age-recipients`
    /// since the last verified state are properly signed by authorized recipients.
    ///
    /// - Returns: The verification result
    /// - Throws: AppError if repository access fails
    func verifyAfterPull() throws -> TrustVerificationResult {
        // Only applicable for passage stores
        let cryptoAgent = CryptoAgent(storeURL: storeURL)
        guard cryptoAgent.storeType == .passage else {
            return .verified
        }

        guard let gitRepository else {
            throw AppError.repositoryNotSet
        }

        let trustManager = TrustManager(storeURL: storeURL)

        // Check if trust has been initialized
        guard let trustState = trustManager.loadTrustState(), trustState.initialized else {
            return .trustNotInitialized
        }

        // Verify commits since last verified
        let issues = try trustManager.verifyCommitsSince(
            lastVerifiedSHA: trustState.lastVerifiedCommitSHA,
            repository: gitRepository.repository
        )

        if issues.isEmpty {
            // All verified - update trust state to current HEAD
            try updateTrustStateToHead(trustManager: trustManager, gitRepository: gitRepository)
            return .verified
        }

        return .issues(issues)
    }

    /// Initialize trust on first use (TOFU).
    ///
    /// Called when the user accepts the current `.age-recipients` as trusted.
    /// This establishes the initial trust anchor.
    ///
    /// - Throws: TrustManagerError if initialization fails
    func initializeTrust() throws {
        guard let gitRepository else {
            throw AppError.repositoryNotSet
        }

        let trustManager = TrustManager(storeURL: storeURL)
        _ = try trustManager.initializeTrustFromCurrentState(repository: gitRepository.repository)
    }

    /// Accept trust verification issues and update trust state.
    ///
    /// Called when the user manually reviews and accepts changes to `.age-recipients`
    /// that failed verification. This updates the trust state to the current HEAD.
    ///
    /// - Throws: TrustManagerError or AppError if update fails
    func acceptTrustIssues() throws {
        guard let gitRepository else {
            throw AppError.repositoryNotSet
        }

        let trustManager = TrustManager(storeURL: storeURL)
        try updateTrustStateToHead(trustManager: trustManager, gitRepository: gitRepository)
    }

    /// Update trust state to the current HEAD commit.
    ///
    /// - Parameters:
    ///   - trustManager: The TrustManager instance
    ///   - gitRepository: The GitRepository instance
    /// - Throws: TrustManagerError if update fails
    private func updateTrustStateToHead(trustManager: TrustManager, gitRepository: GitRepository) throws {
        // Get current HEAD commit
        guard let headCommit = try? gitRepository.getRecentCommits(count: 1).first else {
            throw TrustManagerError.repositoryError("Could not get HEAD commit")
        }

        // Get the SHA (it may be optional on GTCommit, use fallback)
        let headSHA = headCommit.sha ?? ""
        guard !headSHA.isEmpty else {
            throw TrustManagerError.repositoryError("HEAD commit has no SHA")
        }

        // Read current recipients
        let recipientsURL = storeURL.appendingPathComponent(".age-recipients")
        let recipientsContent = (try? String(contentsOf: recipientsURL, encoding: .utf8)) ?? ""
        let currentRecipients = recipientsContent
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }

        try trustManager.updateTrustState(
            newCommitSHA: headSHA,
            newRecipients: currentRecipients
        )
    }

    /// Check if trust verification is needed for this store.
    ///
    /// - Returns: true if this is a passage store
    var requiresTrustVerification: Bool {
        let cryptoAgent = CryptoAgent(storeURL: storeURL)
        return cryptoAgent.storeType == .passage
    }

    /// Check if trust has been initialized for this store.
    ///
    /// - Returns: true if trust state exists and is initialized
    var isTrustInitialized: Bool {
        let trustManager = TrustManager(storeURL: storeURL)
        return trustManager.isTrustInitialized
    }
}
