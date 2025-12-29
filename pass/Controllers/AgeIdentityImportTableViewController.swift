//
//  AgeIdentityImportTableViewController.swift
//  pass
//
//  Created for Pass for iOS.
//  Copyright © 2024 Bob Sun. All rights reserved.
//

import passKit
import UIKit

class AgeIdentityImportTableViewController: UITableViewController {

    private var identityTextView: UITextView!
    private var saveBarButtonItem: UIBarButtonItem!

    private let keychain = AppKeychain.shared

    private enum Section: Int, CaseIterable {
        case explanation
        case identity
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "ImportAgeIdentity".localize()

        // Setup navigation bar
        saveBarButtonItem = UIBarButtonItem(
            title: "Save".localize(),
            style: .done,
            target: self,
            action: #selector(save(_:))
        )
        saveBarButtonItem.isEnabled = false
        navigationItem.rightBarButtonItem = saveBarButtonItem

        let pasteButton = UIBarButtonItem(
            title: "Paste".localize(),
            style: .plain,
            target: self,
            action: #selector(paste(_:))
        )
        navigationItem.leftBarButtonItem = pasteButton

        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
        tableView.estimatedRowHeight = 170
        tableView.rowHeight = UITableView.automaticDimension
    }

    // MARK: - Table View

    override func numberOfSections(in tableView: UITableView) -> Int {
        Section.allCases.count
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        1
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        switch Section(rawValue: section)! {
        case .explanation:
            return nil
        case .identity:
            return "AgeIdentity".localize()
        }
    }

    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        switch Section(rawValue: section)! {
        case .explanation:
            return "AgeIdentityImportExplanation.".localize()
        case .identity:
            return nil
        }
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        switch Section(rawValue: indexPath.section)! {
        case .explanation:
            let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
            cell.selectionStyle = .none
            cell.textLabel?.text = nil
            cell.contentView.subviews.forEach { $0.removeFromSuperview() }
            return cell

        case .identity:
            let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
            cell.selectionStyle = .none

            // Remove any existing text view
            cell.contentView.subviews.forEach { $0.removeFromSuperview() }

            // Create text view
            identityTextView = UITextView()
            identityTextView.translatesAutoresizingMaskIntoConstraints = false
            identityTextView.font = .monospacedSystemFont(ofSize: 14, weight: .regular)
            identityTextView.autocapitalizationType = .none
            identityTextView.autocorrectionType = .no
            identityTextView.spellCheckingType = .no
            identityTextView.delegate = self
            identityTextView.isScrollEnabled = false
            identityTextView.backgroundColor = .clear

            cell.contentView.addSubview(identityTextView)
            NSLayoutConstraint.activate([
                identityTextView.topAnchor.constraint(equalTo: cell.contentView.topAnchor, constant: 8),
                identityTextView.bottomAnchor.constraint(equalTo: cell.contentView.bottomAnchor, constant: -8),
                identityTextView.leadingAnchor.constraint(equalTo: cell.contentView.leadingAnchor, constant: 16),
                identityTextView.trailingAnchor.constraint(equalTo: cell.contentView.trailingAnchor, constant: -16),
                identityTextView.heightAnchor.constraint(greaterThanOrEqualToConstant: 100),
            ])

            return cell
        }
    }

    // MARK: - Actions

    @objc
    private func save(_: Any) {
        guard let identityString = identityTextView?.text?.trimmingCharacters(in: .whitespacesAndNewlines),
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
        keychain.add(string: identityString, for: CryptoAgent.ageIdentityKeychainKey)

        // Show success and pop
        let alert = UIAlertController(
            title: "AgeIdentityImported".localize(),
            message: "AgeIdentityImportedMessage".localize(),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Ok".localize(), style: .default) { [weak self] _ in
            self?.navigationController?.popViewController(animated: true)
        })
        present(alert, animated: true)
    }

    @objc
    private func paste(_: Any) {
        if let pasteboardString = UIPasteboard.general.string {
            identityTextView?.text = pasteboardString
            updateSaveButton()
            // Clear the pasteboard after 45s for security
            SecurePasteboard.shared.copy(textToCopy: pasteboardString)
        }
    }

    private func updateSaveButton() {
        let text = identityTextView?.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        saveBarButtonItem?.isEnabled = text.hasPrefix("AGE-SECRET-KEY-")
    }

    private func showError(_ message: String) {
        Utils.alert(title: "Error".localize(), message: message, controller: self, completion: nil)
    }
}

extension AgeIdentityImportTableViewController: UITextViewDelegate {
    func textViewDidChange(_ textView: UITextView) {
        updateSaveButton()
        // Recalculate cell height
        tableView.beginUpdates()
        tableView.endUpdates()
    }

    func textView(_: UITextView, shouldChangeTextIn _: NSRange, replacementText text: String) -> Bool {
        if text == UIPasteboard.general.string {
            // User pastes something, do the copy here again and clear the pasteboard in 45s
            SecurePasteboard.shared.copy(textToCopy: text)
        }
        return true
    }
}
