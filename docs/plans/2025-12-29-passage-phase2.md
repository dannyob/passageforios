# Passage Support Phase 2: Software Identity Integration

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable Pass for iOS to decrypt passage (.age) password stores using software age identities (AGE-SECRET-KEY-...).

**Architecture:** Wire PasswordStore to use the existing CryptoAgent (built in Phase 1), which dispatches to either PGPAgent or AgeInterface based on detected store type. Add UI for importing software age identities. Hardware-backed decryption (Secure Enclave, YubiKey) deferred to Phase 3.

**Tech Stack:**
- Existing `CryptoAgent` and `AgeInterface` from Phase 1
- Go age library via gomobile (already integrated)
- KeyFileManager pattern for identity storage

---

## Task 1: Migrate PasswordStore to use CryptoAgent

**Files:**
- Modify: `passKit/Models/PasswordStore.swift:384-418`
- Modify: `passKit/Crypto/CryptoAgent.swift` (add keyID support)
- Create: `passKitTests/Models/PasswordStoreCryptoAgentTest.swift`

**Step 1: Add findRecipientID helper for age stores**

Add after `findGPGID` function (line 470) in `passKit/Models/PasswordStore.swift`:

```swift
func findAgeRecipients(from url: URL) -> String {
    var path = url
    while !FileManager.default.fileExists(atPath: path.appendingPathComponent(".age-recipients").path),
          path.path != "file:///" {
        path = path.deletingLastPathComponent()
    }
    path = path.appendingPathComponent(".age-recipients")

    return (try? String(contentsOf: path))?.trimmed ?? ""
}
```

**Step 2: Update PasswordStore to use CryptoAgent**

Replace lines 384-418 in `passKit/Models/PasswordStore.swift`:

```swift
public func decrypt(passwordEntity: PasswordEntity, keyID: String? = nil, requestPGPKeyPassphrase: @escaping (String) -> String) throws -> Password {
    let url = passwordEntity.fileURL(in: storeURL)
    let encryptedData = try Data(contentsOf: url)

    // Use CryptoAgent which dispatches based on store type
    let cryptoAgent = CryptoAgent(storeURL: storeURL)

    let data: Data? = try {
        switch cryptoAgent.storeType {
        case .pass:
            // PGP path - use keyID if enabled
            if Defaults.isEnableGPGIDOn {
                let keyID = keyID ?? findGPGID(from: url)
                return try cryptoAgent.decrypt(encryptedData: encryptedData, keyID: keyID, requestPassphrase: requestPGPKeyPassphrase)
            }
            return try cryptoAgent.decrypt(encryptedData: encryptedData, requestPassphrase: requestPGPKeyPassphrase)
        case .passage, .unknown:
            // Age path - no keyID needed (identity determined by stanza matching)
            return try cryptoAgent.decrypt(encryptedData: encryptedData, requestPassphrase: requestPGPKeyPassphrase)
        }
    }()
    guard let decryptedData = data else {
        throw AppError.decryption
    }
    let plainText = String(data: decryptedData, encoding: .utf8) ?? ""
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
        let keyID = keyID ?? findGPGID(from: encryptedDataPath)
        if Defaults.isEnableGPGIDOn {
            return try cryptoAgent.encrypt(plainData: password.plainData, keyID: keyID)
        }
        return try cryptoAgent.encrypt(plainData: password.plainData)
    case .passage, .unknown:
        return try cryptoAgent.encrypt(plainData: password.plainData)
    }
}
```

**Step 3: Add keyID parameter to CryptoAgent methods**

In `passKit/Crypto/CryptoAgent.swift`, update the decrypt signature to accept optional keyID:

```swift
public func decrypt(
    encryptedData: Data,
    keyID: String? = nil,
    requestPassphrase: @escaping (String) -> String
) throws -> Data {
    try initKeys()

    switch storeType {
    case .pass:
        return try decryptWithPGP(encryptedData: encryptedData, keyID: keyID, requestPassphrase: requestPassphrase)
    case .passage:
        return try decryptWithAge(encryptedData: encryptedData, requestPassphrase: requestPassphrase)
    case .unknown:
        throw CryptoError.decryptionFailed("Unknown store type")
    }
}
```

Update `decryptWithPGP` to pass keyID:

```swift
private func decryptWithPGP(
    encryptedData: Data,
    keyID: String?,
    requestPassphrase: @escaping (String) -> String
) throws -> Data {
    if pgpAgent == nil {
        pgpAgent = PGPAgent(keyStore: keyStore)
    }

    let previousDecryptStatus = latestDecryptStatus
    do {
        let result: Data?
        if let keyID = keyID {
            result = try pgpAgent?.decrypt(encryptedData: encryptedData, keyID: keyID, requestPGPKeyPassphrase: requestPassphrase)
        } else {
            result = try pgpAgent?.decrypt(encryptedData: encryptedData, requestPGPKeyPassphrase: requestPassphrase)
        }
        guard let decrypted = result else {
            throw CryptoError.decryptionFailed("PGP decryption returned nil")
        }
        latestDecryptStatus = true
        return decrypted
    } catch {
        latestDecryptStatus = false
        throw error
    }
}
```

Similarly for encrypt:

```swift
public func encrypt(plainData: Data, keyID: String? = nil) throws -> Data {
    try initKeys()

    switch storeType {
    case .pass:
        return try encryptWithPGP(plainData: plainData, keyID: keyID)
    case .passage:
        return try encryptWithAge(plainData: plainData)
    case .unknown:
        throw CryptoError.encryptionFailed("Unknown store type")
    }
}

private func encryptWithPGP(plainData: Data, keyID: String?) throws -> Data {
    if pgpAgent == nil {
        pgpAgent = PGPAgent(keyStore: keyStore)
    }
    guard let pgp = pgpAgent else {
        throw CryptoError.encryptionFailed("PGP not initialized")
    }
    if let keyID = keyID {
        return try pgp.encrypt(plainData: plainData, keyID: keyID)
    }
    return try pgp.encrypt(plainData: plainData)
}
```

**Step 4: Run existing tests to verify no regression**

Run: `xcodebuild test -scheme pass -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:passKitTests/PasswordStoreTest 2>&1 | tail -30`
Expected: All existing tests PASS (PGP path unchanged)

**Step 5: Commit**

```bash
git add passKit/Models/PasswordStore.swift passKit/Crypto/CryptoAgent.swift
git commit -m "refactor: migrate PasswordStore to use CryptoAgent

Routes decrypt/encrypt through CryptoAgent which dispatches to
PGPAgent or AgeInterface based on detected store type."
```

---

## Task 2: Add age identity keychain storage

**Files:**
- Modify: `passKit/Crypto/CryptoAgent.swift` (load age identity from keychain)
- Modify: `passKit/Helpers/KeychainKey.swift` (add age identity key)

**Step 1: Add age identity keychain key**

Check if there's a KeychainKey enum or similar, otherwise add constant to CryptoAgent.

In `passKit/Crypto/CryptoAgent.swift`, verify/add:

```swift
private static let ageIdentityKeychainKey = "age.identity"
```

**Step 2: Update initKeys() to load age identity from keychain**

Verify the initKeys() passage case loads from keychain (should already exist from Phase 1):

```swift
case .passage:
    // Try Secure Enclave first
    if let seIdentity = try? SecureEnclaveIdentity.load(tag: Self.secureEnclaveIdentityTag) {
        secureEnclaveIdentity = seIdentity
        return
    }
    // Fall back to software identity from keychain
    if let identityString = keyStore.get(for: Self.ageIdentityKeychainKey) {
        ageInterface = try AgeInterface(identityString: identityString)
    } else {
        throw CryptoError.identityNotFound
    }
```

**Step 3: Commit if changes made**

```bash
git add passKit/Crypto/CryptoAgent.swift
git commit -m "feat(crypto): ensure age identity loads from keychain"
```

---

## Task 3: Create AgeIdentityImportTableViewController

**Files:**
- Create: `pass/Controllers/AgeIdentityImportTableViewController.swift`
- Modify: `pass/Base.lproj/Main.storyboard` (add view controller)
- Modify: `pass/en.lproj/Localizable.strings` (add strings)

**Step 1: Create the import view controller**

Create `pass/Controllers/AgeIdentityImportTableViewController.swift`:

```swift
//
//  AgeIdentityImportTableViewController.swift
//  pass
//

import passKit
import UIKit

class AgeIdentityImportTableViewController: UITableViewController {

    @IBOutlet var identityTextView: UITextView!
    @IBOutlet var saveBarButtonItem: UIBarButtonItem!

    private let keychain = AppKeychain.shared
    private let ageIdentityKeychainKey = "age.identity"

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "ImportAgeIdentity".localize()
        identityTextView.delegate = self
        identityTextView.font = .monospacedSystemFont(ofSize: 14, weight: .regular)
        identityTextView.autocapitalizationType = .none
        identityTextView.autocorrectionType = .no
        identityTextView.spellCheckingType = .no
        updateSaveButton()
    }

    private func updateSaveButton() {
        let text = identityTextView.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        saveBarButtonItem.isEnabled = text.hasPrefix("AGE-SECRET-KEY-")
    }

    @IBAction
    private func save(_: Any) {
        guard let identityString = identityTextView.text?.trimmingCharacters(in: .whitespacesAndNewlines),
              identityString.hasPrefix("AGE-SECRET-KEY-") else {
            showError("InvalidAgeIdentity".localize())
            return
        }

        // Validate the identity can be parsed
        do {
            _ = try AgeInterface(identityString: identityString)
        } catch {
            showError("InvalidAgeIdentity".localize() + ": " + error.localizedDescription)
            return
        }

        // Store in keychain
        keychain.add(string: identityString, for: ageIdentityKeychainKey)

        // Show success and pop
        let alert = UIAlertController(
            title: "AgeIdentityImported".localize(),
            message: "AgeIdentityImportedMessage".localize(),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "OK".localize(), style: .default) { [weak self] _ in
            self?.navigationController?.popViewController(animated: true)
        })
        present(alert, animated: true)
    }

    @IBAction
    private func paste(_: Any) {
        if let pasteboardString = UIPasteboard.general.string {
            identityTextView.text = pasteboardString
            updateSaveButton()
        }
    }

    private func showError(_ message: String) {
        let alert = UIAlertController(title: "Error".localize(), message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK".localize(), style: .default))
        present(alert, animated: true)
    }
}

extension AgeIdentityImportTableViewController: UITextViewDelegate {
    func textViewDidChange(_ textView: UITextView) {
        updateSaveButton()
    }
}
```

**Step 2: Add localization strings**

Add to `pass/en.lproj/Localizable.strings`:

```
"ImportAgeIdentity" = "Import Age Identity";
"InvalidAgeIdentity" = "Invalid age identity format";
"AgeIdentityImported" = "Identity Imported";
"AgeIdentityImportedMessage" = "Your age identity has been saved. You can now decrypt passwords encrypted to this identity.";
"AgeIdentityPlaceholder" = "Paste your AGE-SECRET-KEY-... here";
```

**Step 3: Add to storyboard**

In `pass/Base.lproj/Main.storyboard`:
- Add new UITableViewController with custom class `AgeIdentityImportTableViewController`
- Add static table view with one section containing a UITextView cell
- Add navigation bar with Cancel (left) and Save (right) buttons
- Connect outlets: `identityTextView`, `saveBarButtonItem`
- Connect actions: `save:`, `paste:`

**Step 4: Commit**

```bash
git add pass/Controllers/AgeIdentityImportTableViewController.swift
git add pass/Base.lproj/Main.storyboard
git add pass/en.lproj/Localizable.strings
git commit -m "feat(ui): add age identity import screen

Allows importing AGE-SECRET-KEY-... software identities for passage stores."
```

---

## Task 4: Add age identity entry point in Settings

**Files:**
- Modify: `pass/Controllers/SettingsTableViewController.swift`
- Modify: `pass/Base.lproj/Main.storyboard`

**Step 1: Add IBOutlet for age identity cell**

In `SettingsTableViewController.swift`, add outlet:

```swift
@IBOutlet var ageIdentityTableViewCell: UITableViewCell!
```

**Step 2: Add cell status method**

```swift
private func setAgeIdentityCellDetailText() {
    let keychain = AppKeychain.shared
    if let _: String = keychain.get(for: "age.identity") {
        ageIdentityTableViewCell.detailTextLabel?.text = "Configured".localize()
        ageIdentityTableViewCell.detailTextLabel?.textColor = .systemGreen
    } else {
        ageIdentityTableViewCell.detailTextLabel?.text = "NotSet".localize()
        ageIdentityTableViewCell.detailTextLabel?.textColor = .secondaryLabel
    }
}
```

**Step 3: Call in viewDidLoad and viewWillAppear**

Add to `viewDidLoad()`:
```swift
setAgeIdentityCellDetailText()
```

Add to `viewWillAppear(_:)`:
```swift
setAgeIdentityCellDetailText()
```

**Step 4: Handle cell selection**

In `tableView(_:didSelectRowAt:)`, add:

```swift
case ageIdentityTableViewCell:
    showAgeIdentityImport()
```

Add method:

```swift
private func showAgeIdentityImport() {
    let storyboard = UIStoryboard(name: "Main", bundle: nil)
    if let vc = storyboard.instantiateViewController(withIdentifier: "AgeIdentityImportTableViewController") as? AgeIdentityImportTableViewController {
        navigationController?.pushViewController(vc, animated: true)
    }
}
```

**Step 5: Add cell in storyboard**

In Main.storyboard Settings scene:
- Add row in KEYS section (or new AGE section) with title "Age Identity"
- Style: Right Detail (Value1)
- Add disclosure indicator accessory
- Connect outlet to `ageIdentityTableViewCell`

**Step 6: Commit**

```bash
git add pass/Controllers/SettingsTableViewController.swift
git add pass/Base.lproj/Main.storyboard
git commit -m "feat(ui): add age identity entry in Settings

Links to import screen for AGE-SECRET-KEY software identities."
```

---

## Task 5: Add age identity delete option

**Files:**
- Modify: `pass/Controllers/SettingsTableViewController.swift`

**Step 1: Show action sheet for age identity cell**

Replace `showAgeIdentityImport()` with:

```swift
private func showAgeIdentityActionSheet() {
    let keychain = AppKeychain.shared
    let hasIdentity: Bool = keychain.get(for: "age.identity") != nil

    let alert = UIAlertController(title: "AgeIdentity".localize(), message: nil, preferredStyle: .actionSheet)

    alert.addAction(UIAlertAction(title: "ImportAgeIdentity".localize(), style: .default) { [weak self] _ in
        self?.showAgeIdentityImport()
    })

    if hasIdentity {
        alert.addAction(UIAlertAction(title: "DeleteAgeIdentity".localize(), style: .destructive) { [weak self] _ in
            self?.deleteAgeIdentity()
        })
    }

    alert.addAction(UIAlertAction(title: "Cancel".localize(), style: .cancel))

    if let popover = alert.popoverPresentationController {
        popover.sourceView = ageIdentityTableViewCell
        popover.sourceRect = ageIdentityTableViewCell.bounds
    }

    present(alert, animated: true)
}

private func showAgeIdentityImport() {
    let storyboard = UIStoryboard(name: "Main", bundle: nil)
    if let vc = storyboard.instantiateViewController(withIdentifier: "AgeIdentityImportTableViewController") as? AgeIdentityImportTableViewController {
        navigationController?.pushViewController(vc, animated: true)
    }
}

private func deleteAgeIdentity() {
    let alert = UIAlertController(
        title: "DeleteAgeIdentity".localize(),
        message: "DeleteAgeIdentityWarning".localize(),
        preferredStyle: .alert
    )
    alert.addAction(UIAlertAction(title: "Cancel".localize(), style: .cancel))
    alert.addAction(UIAlertAction(title: "Delete".localize(), style: .destructive) { [weak self] _ in
        AppKeychain.shared.removeContent(for: "age.identity")
        self?.setAgeIdentityCellDetailText()
    })
    present(alert, animated: true)
}
```

**Step 2: Update cell selection handler**

```swift
case ageIdentityTableViewCell:
    showAgeIdentityActionSheet()
```

**Step 3: Add localization strings**

Add to `pass/en.lproj/Localizable.strings`:

```
"AgeIdentity" = "Age Identity";
"DeleteAgeIdentity" = "Delete Age Identity";
"DeleteAgeIdentityWarning" = "You will no longer be able to decrypt passwords encrypted to this identity.";
"Configured" = "Configured";
```

**Step 4: Commit**

```bash
git add pass/Controllers/SettingsTableViewController.swift
git add pass/en.lproj/Localizable.strings
git commit -m "feat(ui): add delete option for age identity

Shows action sheet with import/delete options for age identity."
```

---

## Task 6: Integration test

**Files:**
- Test manually with a passage store

**Step 1: Create test passage store**

On your Mac:
```bash
# Install age and passage
brew install age
brew install passage  # or clone from github.com/FiloSottile/passage

# Generate test identity
age-keygen -o test-identity.txt
cat test-identity.txt  # Copy the AGE-SECRET-KEY-... line

# Initialize passage store
export PASSAGE_DIR=~/test-passage-store
mkdir -p $PASSAGE_DIR
age-keygen -o $PASSAGE_DIR/.age-identities
cat $PASSAGE_DIR/.age-identities | grep "^age1" > $PASSAGE_DIR/.age-recipients

# Add a test password
echo "testpassword123" | passage insert test/mysite
```

**Step 2: Test in app**

1. Clone/sync the test-passage-store to the iOS app
2. Go to Settings → Age Identity → Import
3. Paste the AGE-SECRET-KEY-... from test-identity.txt
4. Save
5. Navigate to test/mysite password
6. Verify it decrypts to "testpassword123"

**Step 3: Commit any fixes**

```bash
git add -A
git commit -m "fix: integration fixes for passage support"
```

---

## Future Work (Phase 3)

### Task 7: Secure Enclave age decryption
- Parse age file header to extract p256tag stanzas
- Implement HPKE with CryptoKit (iOS 17+) or manual ECDH + HKDF
- Unwrap file key using Secure Enclave ECDH
- Decrypt payload with ChaCha20-Poly1305

### Task 8: YubiKey PIV support
- Implement PIV applet selection (different from OpenPGP)
- P-256 ECDH on PIV slot 9d
- PIN handling for PIV
- Integration with age decryption flow

---

## Testing Checklist

- [ ] Existing PGP tests still pass
- [ ] PasswordStore.decrypt routes to CryptoAgent
- [ ] CryptoAgent detects .age-recipients and uses AgeInterface
- [ ] Age identity can be imported via Settings
- [ ] Age identity can be deleted via Settings
- [ ] Settings shows "Configured" when age identity present
- [ ] Passage store decrypts with software identity
- [ ] Passage store encrypts new passwords
