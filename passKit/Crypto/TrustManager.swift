//
//  TrustManager.swift
//  passKit
//
//  Manages trust state for age recipients verification.
//  Implements Trust On First Use (TOFU) and verification chain tracking.
//

import Foundation
import ObjectiveGit

/// Represents a trust verification issue found during commit verification.
public struct TrustVerificationIssue: Equatable {
    /// Types of trust verification issues
    public enum IssueType: Equatable {
        case unsignedCommit
        case unauthorizedSigner
        case signatureVerificationFailed
        case couldNotExtractSignature
    }

    /// The SHA of the commit with the issue
    public let commitSHA: String

    /// The commit message (for display purposes)
    public let commitMessage: String?

    /// The type of issue encountered
    public let issueType: IssueType

    /// Additional details about the issue
    public let details: String?

    public init(commitSHA: String, commitMessage: String? = nil, issueType: IssueType, details: String? = nil) {
        self.commitSHA = commitSHA
        self.commitMessage = commitMessage
        self.issueType = issueType
        self.details = details
    }
}

/// Errors that can occur during trust management operations.
public enum TrustManagerError: Error, Equatable {
    case stateNotInitialized
    case saveFailed(String)
    case loadFailed(String)
    case repositoryError(String)
    case commitNotFound(String)
}

/// Manages trust state for age recipients verification.
///
/// When a user clones or pulls a passage repository:
/// 1. If no trust state exists (first time): Trust On First Use (TOFU) - trust current .age-recipients
/// 2. If trust state exists: Verify all commits since last verified that modified .age-recipients
///
/// Trust state is stored locally in `.passage-trust.json` and added to `.gitignore`
/// to prevent syncing across devices.
public class TrustManager {
    /// Trust state stored per repository
    public struct TrustState: Codable, Equatable {
        /// SHA of the last successfully verified commit
        public var lastVerifiedCommitSHA: String

        /// Age recipients that were trusted at the last verified commit
        public var trustedRecipients: [String]

        /// Whether trust has been initialized (TOFU completed)
        public var initialized: Bool

        /// Path to the repository (for validation)
        public var repositoryPath: String

        public init(
            lastVerifiedCommitSHA: String,
            trustedRecipients: [String],
            initialized: Bool,
            repositoryPath: String
        ) {
            self.lastVerifiedCommitSHA = lastVerifiedCommitSHA
            self.trustedRecipients = trustedRecipients
            self.initialized = initialized
            self.repositoryPath = repositoryPath
        }
    }

    /// The trust state file name (kept local, not synced)
    private static let trustStateFileName = ".passage-trust.json"

    /// URL of the password store directory
    private let storeURL: URL

    /// Initialize a TrustManager for a password store
    /// - Parameter storeURL: URL of the password store directory
    public init(storeURL: URL) {
        self.storeURL = storeURL
    }

    // MARK: - Trust State Persistence

    /// URL of the trust state file
    private var trustStateFileURL: URL {
        storeURL.appendingPathComponent(Self.trustStateFileName)
    }

    /// Load trust state from persistent storage
    /// - Returns: The trust state if it exists, nil otherwise
    public func loadTrustState() -> TrustState? {
        guard FileManager.default.fileExists(atPath: trustStateFileURL.path) else {
            return nil
        }

        do {
            let data = try Data(contentsOf: trustStateFileURL)
            return try JSONDecoder().decode(TrustState.self, from: data)
        } catch {
            // If we can't load the trust state, treat it as if it doesn't exist
            return nil
        }
    }

    /// Save trust state to persistent storage
    /// - Parameter state: The trust state to save
    /// - Throws: TrustManagerError.saveFailed if the save fails
    public func saveTrustState(_ state: TrustState) throws {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(state)
            try data.write(to: trustStateFileURL, options: .atomic)

            // Ensure the trust file is in .gitignore
            addToGitignore(Self.trustStateFileName)
        } catch {
            throw TrustManagerError.saveFailed(error.localizedDescription)
        }
    }

    /// Delete the trust state file
    public func deleteTrustState() {
        try? FileManager.default.removeItem(at: trustStateFileURL)
    }

    // MARK: - Trust Initialization (TOFU)

    /// Initialize trust on first use (TOFU).
    ///
    /// Should be called when no trust state exists. This establishes the initial
    /// trust anchor by trusting the current .age-recipients file and recording
    /// the current commit SHA.
    ///
    /// - Parameters:
    ///   - repository: The git repository
    ///   - currentRecipients: The current age recipients (from .age-recipients)
    ///   - currentCommitSHA: The current HEAD commit SHA
    /// - Returns: The newly created trust state
    /// - Throws: TrustManagerError.saveFailed if saving fails
    public func initializeTrust(
        repository _: GTRepository,
        currentRecipients: [String],
        currentCommitSHA: String
    ) throws -> TrustState {
        let state = TrustState(
            lastVerifiedCommitSHA: currentCommitSHA,
            trustedRecipients: currentRecipients,
            initialized: true,
            repositoryPath: storeURL.path
        )
        try saveTrustState(state)
        return state
    }

    /// Convenience method to initialize trust from the current repository state.
    ///
    /// Reads the current HEAD SHA and .age-recipients content.
    ///
    /// - Parameter repository: The git repository
    /// - Returns: The newly created trust state
    /// - Throws: TrustManagerError if initialization fails
    public func initializeTrustFromCurrentState(repository: GTRepository) throws -> TrustState {
        // Get current HEAD commit SHA
        guard let headRef = try? repository.headReference(),
              let headOID = headRef.targetOID else {
            throw TrustManagerError.repositoryError("Could not get HEAD reference")
        }

        let currentCommitSHA = headOID.sha

        // Get current recipients from HEAD commit
        guard let headCommit = try? repository.lookUpObject(by: headOID, objectType: .commit) as? GTCommit else {
            throw TrustManagerError.commitNotFound(currentCommitSHA)
        }

        let recipientsContent = CommitSignatureVerifier.getAgeRecipientsContent(at: headCommit, in: repository) ?? ""
        let recipients = parseRecipients(recipientsContent)

        return try initializeTrust(
            repository: repository,
            currentRecipients: recipients,
            currentCommitSHA: currentCommitSHA
        )
    }

    // MARK: - Trust Verification

    /// Verify commits since the last trusted state.
    ///
    /// Walks through all commits from `lastVerifiedSHA` to HEAD that modify
    /// `.age-recipients`, checking that each is properly signed by an authorized
    /// recipient.
    ///
    /// - Parameters:
    ///   - lastVerifiedSHA: The SHA of the last verified commit
    ///   - repository: The git repository
    /// - Returns: List of verification issues (empty if all valid)
    /// - Throws: TrustManagerError if verification cannot be performed
    public func verifyCommitsSince(
        lastVerifiedSHA: String,
        repository: GTRepository
    ) throws -> [TrustVerificationIssue] {
        var issues: [TrustVerificationIssue] = []

        // Get commits that modified .age-recipients since lastVerifiedSHA
        let commitsToVerify = try getCommitsModifyingRecipients(
            since: lastVerifiedSHA,
            in: repository
        )

        // Track the authorized recipients as we walk forward through commits
        var authorizedRecipients = loadTrustState()?.trustedRecipients ?? []

        for commit in commitsToVerify {
            let verificationResult = CommitSignatureVerifier.verifyCommit(
                commit,
                authorizedRecipients: authorizedRecipients.joined(separator: "\n"),
                verifyCryptographicSignature: true
            )

            if !verificationResult.isSigned {
                issues.append(TrustVerificationIssue(
                    commitSHA: commit.sha ?? "unknown",
                    commitMessage: commit.message,
                    issueType: .unsignedCommit,
                    details: "Commit modifying .age-recipients is not signed"
                ))
                continue
            }

            if !verificationResult.errorMessage.isEmpty {
                issues.append(TrustVerificationIssue(
                    commitSHA: commit.sha ?? "unknown",
                    commitMessage: commit.message,
                    issueType: .signatureVerificationFailed,
                    details: verificationResult.errorMessage
                ))
                continue
            }

            if !verificationResult.isAuthorized {
                issues.append(TrustVerificationIssue(
                    commitSHA: commit.sha ?? "unknown",
                    commitMessage: commit.message,
                    issueType: .unauthorizedSigner,
                    details: "Signer \(verificationResult.signerAgeKey) is not in the authorized recipients list"
                ))
                continue
            }

            // Update authorized recipients for the next commit in the chain
            if let newRecipients = CommitSignatureVerifier.getAgeRecipientsContent(at: commit, in: repository) {
                authorizedRecipients = parseRecipients(newRecipients)
            }
        }

        return issues
    }

    /// Get all commits that modified .age-recipients since a given commit SHA.
    ///
    /// - Parameters:
    ///   - sha: The starting commit SHA (exclusive)
    ///   - repository: The git repository
    /// - Returns: Array of commits that modified .age-recipients, ordered oldest to newest
    /// - Throws: TrustManagerError if commits cannot be enumerated
    private func getCommitsModifyingRecipients(
        since sha: String,
        in repository: GTRepository
    ) throws -> [GTCommit] {
        guard let headRef = try? repository.headReference(),
              let headOID = headRef.targetOID else {
            throw TrustManagerError.repositoryError("Could not get HEAD reference")
        }

        var commitsToVerify: [GTCommit] = []

        do {
            let enumerator = try GTEnumerator(repository: repository)
            try enumerator.pushSHA(headOID.sha)

            // Walk commits from HEAD backwards until we reach lastVerifiedSHA
            while let commit = try? enumerator.nextObject(withSuccess: nil) {
                // Stop when we reach the last verified commit
                if commit.sha == sha {
                    break
                }

                // Check if this commit modifies .age-recipients
                if CommitSignatureVerifier.modifiesAgeRecipients(commit, in: repository) {
                    commitsToVerify.append(commit)
                }
            }
        } catch {
            throw TrustManagerError.repositoryError("Failed to enumerate commits: \(error.localizedDescription)")
        }

        // Reverse to get oldest-to-newest order for proper chain verification
        return commitsToVerify.reversed()
    }

    // MARK: - Trust State Updates

    /// Update trust state after successful verification.
    ///
    /// Called when all commits since the last verified state have been
    /// successfully verified.
    ///
    /// - Parameters:
    ///   - newCommitSHA: The new last verified commit SHA
    ///   - newRecipients: The current trusted recipients
    /// - Throws: TrustManagerError.saveFailed if saving fails
    public func updateTrustState(
        newCommitSHA: String,
        newRecipients: [String]
    ) throws {
        var state = loadTrustState() ?? TrustState(
            lastVerifiedCommitSHA: newCommitSHA,
            trustedRecipients: newRecipients,
            initialized: true,
            repositoryPath: storeURL.path
        )
        state.lastVerifiedCommitSHA = newCommitSHA
        state.trustedRecipients = newRecipients
        try saveTrustState(state)
    }

    /// Check if trust has been initialized for this repository.
    /// - Returns: true if trust state exists and is initialized
    public var isTrustInitialized: Bool {
        loadTrustState()?.initialized ?? false
    }

    // MARK: - Helper Methods

    /// Parse recipients string into array of individual recipients.
    ///
    /// Filters out empty lines and comments.
    ///
    /// - Parameter content: The contents of .age-recipients file
    /// - Returns: Array of recipient strings
    private func parseRecipients(_ content: String) -> [String] {
        content
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
    }

    /// Add an entry to .gitignore if not already present.
    ///
    /// - Parameter entry: The entry to add to .gitignore
    private func addToGitignore(_ entry: String) {
        let gitignoreURL = storeURL.appendingPathComponent(".gitignore")

        // Read existing content
        var content = (try? String(contentsOf: gitignoreURL, encoding: .utf8)) ?? ""

        // Check if entry already exists
        let lines = content.components(separatedBy: .newlines)
        if lines.contains(entry) {
            return
        }

        // Add entry
        if !content.isEmpty, !content.hasSuffix("\n") {
            content += "\n"
        }
        content += entry + "\n"

        // Write back
        try? content.write(to: gitignoreURL, atomically: true, encoding: .utf8)
    }
}
