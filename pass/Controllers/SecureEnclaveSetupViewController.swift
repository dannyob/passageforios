//
//  SecureEnclaveSetupViewController.swift
//  pass
//
//  Created by Pass for iOS.
//  Copyright © 2024 Bob Sun. All rights reserved.
//

import CryptoKit
import passKit
import UIKit

class SecureEnclaveSetupViewController: UITableViewController {

    private var identity: SecureEnclaveIdentity?
    private var recipientString: String = ""

    private enum Section: Int, CaseIterable {
        case status
        case recipient
        case actions
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "SecureEnclave".localize()
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
        loadExistingIdentity()
    }

    private func loadExistingIdentity() {
        identity = try? SecureEnclaveIdentity.load(tag: "passforios.age.identity")
        recipientString = identity?.recipient ?? ""
        tableView.reloadData()
    }

    // MARK: - Table View

    override func numberOfSections(in tableView: UITableView) -> Int {
        Section.allCases.count
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        switch Section(rawValue: section)! {
        case .status:
            return 1
        case .recipient:
            return identity != nil ? 1 : 0
        case .actions:
            return identity != nil ? 2 : 1
        }
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        switch Section(rawValue: section)! {
        case .status:
            return "Status".localize()
        case .recipient:
            return identity != nil ? "RecipientForAgeRecipients".localize() : nil
        case .actions:
            return nil
        }
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        cell.textLabel?.font = UIFont.preferredFont(forTextStyle: .body)
        cell.textLabel?.adjustsFontForContentSizeCategory = true

        switch Section(rawValue: indexPath.section)! {
        case .status:
            if SecureEnclave.isAvailable {
                cell.textLabel?.text = identity != nil ? "IdentityConfigured".localize() : "NoIdentity".localize()
                cell.textLabel?.textColor = identity != nil ? .systemGreen : .label
            } else {
                cell.textLabel?.text = "SecureEnclaveNotAvailable".localize()
                cell.textLabel?.textColor = .systemRed
            }
            cell.selectionStyle = .none
            cell.accessoryType = .none

        case .recipient:
            cell.textLabel?.text = recipientString
            cell.textLabel?.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
            cell.textLabel?.numberOfLines = 0
            cell.selectionStyle = .default
            cell.accessoryType = .none
            cell.textLabel?.textColor = .label

        case .actions:
            if indexPath.row == 0 {
                cell.textLabel?.text = identity != nil ? "RegenerateIdentity".localize() : "GenerateIdentity".localize()
                cell.textLabel?.textColor = .systemBlue
            } else {
                cell.textLabel?.text = "DeleteIdentity".localize()
                cell.textLabel?.textColor = .systemRed
            }
            cell.selectionStyle = .default
            cell.accessoryType = .none
        }

        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)

        switch Section(rawValue: indexPath.section)! {
        case .recipient:
            copyRecipient()
        case .actions:
            if indexPath.row == 0 {
                generateIdentity()
            } else {
                deleteIdentity()
            }
        default:
            break
        }
    }

    // MARK: - Actions

    private func generateIdentity() {
        let message = identity != nil
            ? "RegenerateIdentityMessage".localize()
            : "GenerateIdentityMessage".localize()

        let alert = UIAlertController(
            title: identity != nil ? "RegenerateIdentity".localize() : "GenerateIdentity".localize(),
            message: message,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Cancel".localize(), style: .cancel))
        alert.addAction(UIAlertAction(title: "Generate".localize(), style: .default) { [weak self] _ in
            self?.doGenerate()
        })
        present(alert, animated: true)
    }

    private func doGenerate() {
        do {
            identity = try SecureEnclaveIdentity.generate(
                tag: "passforios.age.identity",
                requireBiometric: true
            )
            recipientString = identity?.recipient ?? ""
            tableView.reloadData()

            // Offer to copy
            let alert = UIAlertController(
                title: "IdentityGenerated".localize(),
                message: "CopyRecipientPrompt".localize(),
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: "Copy".localize(), style: .default) { [weak self] _ in
                self?.copyRecipient()
            })
            alert.addAction(UIAlertAction(title: "Later".localize(), style: .cancel))
            present(alert, animated: true)
        } catch {
            showError(error)
        }
    }

    private func copyRecipient() {
        UIPasteboard.general.string = recipientString
        let alert = UIAlertController(title: "Copied".localize(), message: nil, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK".localize(), style: .default))
        present(alert, animated: true)
    }

    private func deleteIdentity() {
        let alert = UIAlertController(
            title: "DeleteIdentity".localize(),
            message: "DeleteIdentityMessage".localize(),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Cancel".localize(), style: .cancel))
        alert.addAction(UIAlertAction(title: "Delete".localize(), style: .destructive) { [weak self] _ in
            SecureEnclaveIdentity.delete(tag: "passforios.age.identity")
            self?.identity = nil
            self?.recipientString = ""
            self?.tableView.reloadData()
        })
        present(alert, animated: true)
    }

    private func showError(_ error: Error) {
        let alert = UIAlertController(
            title: "Error".localize(),
            message: error.localizedDescription,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "OK".localize(), style: .default))
        present(alert, animated: true)
    }
}
