//
//  CommitSignatureVerifier.swift
//  passKit
//
//  Handles extraction and verification of SSH signatures from git commits.
//  Uses ObjectiveGit for commit access and libgit2 for signature extraction.
//

import Crypto
import Foundation
import ObjectiveGit

/// Errors that can occur during signature verification
public enum CommitSignatureError: Error, Equatable {
    case signatureNotFound
    case extractionFailed(String)
    case verificationFailed(String)
    case repositoryNotAvailable
    case commitNotFound
}

/// Result of signature extraction from a commit
public struct CommitSignatureData {
    /// The armored SSH signature (-----BEGIN SSH SIGNATURE-----)
    public let signature: String

    /// The commit content that was signed (commit without gpgsig header)
    public let signedData: Data

    public init(signature: String, signedData: Data) {
        self.signature = signature
        self.signedData = signedData
    }
}

/// Result of commit signature verification
public struct CommitVerificationResult {
    /// The signer's age recipient string (derived from their SSH ed25519 public key)
    public let signerAgeKey: String

    /// Whether the signer is authorized (their key was in the previous .age-recipients)
    public let isAuthorized: Bool

    /// Error message if verification failed, empty otherwise
    public let errorMessage: String

    /// Whether this commit is signed at all
    public let isSigned: Bool

    public init(signerAgeKey: String = "", isAuthorized: Bool = false, errorMessage: String = "", isSigned: Bool = false) {
        self.signerAgeKey = signerAgeKey
        self.isAuthorized = isAuthorized
        self.errorMessage = errorMessage
        self.isSigned = isSigned
    }
}

/// Handles extraction and verification of SSH signatures from git commits.
///
/// Git SSH signatures are stored in the `gpgsig` header of a commit object.
/// To verify a signature:
/// 1. Extract the signature and signed data using libgit2's `git_commit_extract_signature`
/// 2. Convert the signer's SSH ed25519 public key to an age recipient
/// 3. Check if the age recipient is in the authorized recipients list
public class CommitSignatureVerifier {
    // MARK: - Signature Extraction

    /// Extracts the SSH signature from a git commit.
    ///
    /// Uses libgit2's `git_commit_extract_signature` function via ObjectiveGit.
    /// The signature is stored in the `gpgsig` header field of the commit.
    ///
    /// - Parameter commit: The git commit to extract signature from
    /// - Returns: SignatureData if commit is signed, nil if unsigned
    /// - Throws: CommitSignatureError if extraction fails
    public static func extractSignature(from commit: GTCommit) throws -> CommitSignatureData? {
        // Get the repository from the commit (repository is non-optional in ObjectiveGit)
        let repo = commit.repository

        // Get the raw git_commit pointer
        let gitCommit = commit.git_commit()

        // Get the repository and commit OID for the C API call
        let gitRepo = repo.git_repository()
        var oid = git_commit_id(gitCommit).pointee

        // Prepare output buffers for signature and signed data
        var signatureBuf = git_buf()
        var signedDataBuf = git_buf()

        // Extract the signature using libgit2
        // The field is "gpgsig" for both GPG and SSH signatures
        let result = git_commit_extract_signature(&signatureBuf, &signedDataBuf, gitRepo, &oid, nil)

        // Check result
        if result == GIT_ENOTFOUND.rawValue {
            // Commit is not signed
            return nil
        }

        if result != 0 {
            // Some other error occurred
            git_buf_dispose(&signatureBuf)
            git_buf_dispose(&signedDataBuf)
            throw CommitSignatureError.extractionFailed("git_commit_extract_signature failed with code \(result)")
        }

        // Convert git_buf to Swift strings/data
        defer {
            git_buf_dispose(&signatureBuf)
            git_buf_dispose(&signedDataBuf)
        }

        guard let signaturePtr = signatureBuf.ptr,
              let signedDataPtr = signedDataBuf.ptr else {
            throw CommitSignatureError.extractionFailed("Empty signature or signed data")
        }

        let signature = String(cString: signaturePtr)
        let signedData = Data(bytes: signedDataPtr, count: signedDataBuf.size)

        return CommitSignatureData(signature: signature, signedData: signedData)
    }

    // MARK: - Signature Verification

    /// Verifies a commit's signature against authorized age recipients.
    ///
    /// This implements the trust rule for commits that modify `.age-recipients`:
    /// The signer's age key (derived from their SSH ed25519 public key) must be
    /// present in the authorized recipients list.
    ///
    /// - Parameters:
    ///   - commit: The git commit to verify
    ///   - authorizedRecipients: Newline-separated list of authorized age recipients
    ///     (typically from the PREVIOUS .age-recipients file)
    ///   - verifyCryptographicSignature: If true, also verify the signature cryptographically
    /// - Returns: CommitVerificationResult with verification details
    public static func verifyCommit(
        _ commit: GTCommit,
        authorizedRecipients: String,
        verifyCryptographicSignature: Bool = true
    ) -> CommitVerificationResult {
        // Extract signature
        let sigData: CommitSignatureData?
        do {
            sigData = try extractSignature(from: commit)
        } catch {
            return CommitVerificationResult(
                errorMessage: "Failed to extract signature: \(error.localizedDescription)",
                isSigned: false
            )
        }

        guard let extractedSigData = sigData else {
            // Commit is not signed
            return CommitVerificationResult(isSigned: false)
        }

        // Call the gomobile bindings to verify the signature
        let result = MobileVerifyRecipientsChange(
            extractedSigData.signature,
            extractedSigData.signedData,
            authorizedRecipients,
            verifyCryptographicSignature
        )

        return CommitVerificationResult(
            signerAgeKey: result?.signerAgeKey ?? "",
            isAuthorized: result?.authorized ?? false,
            errorMessage: result?.errorMessage ?? "",
            isSigned: true
        )
    }

    /// Verifies a bootstrap commit (the first commit creating .age-recipients).
    ///
    /// For bootstrap commits, the rule is different: the signer's age key must be
    /// present in the NEW .age-recipients file (self-consistency check).
    ///
    /// - Parameters:
    ///   - commit: The git commit to verify
    ///   - newRecipients: Newline-separated list of recipients in the NEW .age-recipients
    ///   - verifyCryptographicSignature: If true, also verify the signature cryptographically
    /// - Returns: CommitVerificationResult with verification details
    public static func verifyBootstrapCommit(
        _ commit: GTCommit,
        newRecipients: String,
        verifyCryptographicSignature: Bool = true
    ) -> CommitVerificationResult {
        // Extract signature
        let sigData: CommitSignatureData?
        do {
            sigData = try extractSignature(from: commit)
        } catch {
            return CommitVerificationResult(
                errorMessage: "Failed to extract signature: \(error.localizedDescription)",
                isSigned: false
            )
        }

        guard let extractedSigData = sigData else {
            // Commit is not signed
            return CommitVerificationResult(isSigned: false)
        }

        // Call the gomobile bindings to verify the bootstrap commit
        let result = MobileIsBootstrapValid(
            extractedSigData.signature,
            extractedSigData.signedData,
            newRecipients,
            verifyCryptographicSignature
        )

        return CommitVerificationResult(
            signerAgeKey: result?.signerAgeKey ?? "",
            isAuthorized: result?.authorized ?? false,
            errorMessage: result?.errorMessage ?? "",
            isSigned: true
        )
    }

    // MARK: - Utility Methods

    /// Checks if a commit modifies the .age-recipients file.
    ///
    /// - Parameters:
    ///   - commit: The commit to check
    ///   - repository: The repository containing the commit
    /// - Returns: true if the commit modifies .age-recipients
    public static func modifiesAgeRecipients(_ commit: GTCommit, in repository: GTRepository) -> Bool {
        // Get the diff for this commit
        guard let tree = commit.tree else {
            return false
        }

        // Get parent tree (nil for root commit)
        let parentTree = commit.parents.first?.tree

        // Use class method to create diff (GTDiff class method)
        guard let diff = try? GTDiff(oldTree: parentTree, withNewTree: tree, in: repository, options: nil) else {
            // If we can't get the diff, assume it might modify recipients (safer)
            return true
        }

        var modifiesRecipients = false

        // enumerateDeltasUsingBlock doesn't throw - it's an Objective-C block-based method
        diff.enumerateDeltas { delta, stop in
            let oldPath = delta.oldFile?.path ?? ""
            let newPath = delta.newFile?.path ?? ""
            if oldPath == ".age-recipients" || newPath == ".age-recipients" {
                modifiesRecipients = true
                stop.pointee = true
            }
        }

        return modifiesRecipients
    }

    /// Gets the .age-recipients content at a specific commit.
    ///
    /// - Parameters:
    ///   - commit: The commit to read from
    ///   - repository: The repository containing the commit
    /// - Returns: The contents of .age-recipients, or nil if not present
    public static func getAgeRecipientsContent(at commit: GTCommit, in repository: GTRepository) -> String? {
        guard let tree = commit.tree else {
            return nil
        }

        // Use entryWithPath:error: method
        guard let entry = try? tree.entry(withPath: ".age-recipients"),
              let oid = entry.oid else {
            return nil
        }

        // Use repository.lookUpObjectByOID to get the blob
        guard let blob = try? repository.lookUpObject(by: oid, objectType: .blob) as? GTBlob else {
            return nil
        }

        return String(data: blob.data(), encoding: .utf8)
    }
}
