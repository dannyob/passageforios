# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Pass for iOS is a password manager compatible with ZX2C4's Pass (password-store) command line tool. It uses GPG encryption and Git for version control. The app is published as "Pass - Password Store" on the App Store.

## Build Commands

```bash
# First-time setup: build GopenPGP framework (requires Go)
brew install go
./scripts/gopenpgp_build.sh

# Then open pass.xcodeproj in Xcode and build
```

**Testing:**
```bash
# Run all tests via Fastlane
bundle install
bundle exec fastlane test

# Or in Xcode: Cmd+U on the 'pass' scheme
```

**Linting:**
SwiftLint and SwiftFormat run automatically as build phases. Configuration in `.swiftlint.yml` and `.swiftformat`.

## Architecture

### Multi-Target Structure

- **pass** - Main iOS app (production `me.mssun.passforios` and beta `me.mssun.passforiosbeta` variants)
- **passKit** - Shared framework containing all core business logic, models, and crypto
- **passExtension** - Find-Login Action Extension (web autofill for non-Safari browsers)
- **passAutoFillExtension** - Password AutoFill Extension (native Safari/system integration)
- **passShortcuts** - Shortcuts app integration

### Key Directories

```
pass/Controllers/       # View controllers for main app
passKit/
├── Crypto/            # PGP interfaces: PGPAgent orchestrates GopenPGPInterface (primary)
│                      # and ObjectivePGPInterface (fallback)
├── Models/            # Core data models (Password, PasswordStore, GitRepository, etc.)
├── Parser/            # Password file parsing logic
├── Passwords/         # Password generation
└── Helpers/           # AppKeychain, SecurePasteboard, utilities
```

### Crypto Architecture

Dual PGP implementation for iOS 13+:
- **GopenPGPInterface** - Primary, uses custom-built Go framework via gomobile
- **ObjectivePGPInterface** - Fallback using Objective-C library
- **PGPAgent** - Coordinates between interfaces

The GopenPGP.xcframework must be built from the custom fork at `mssun/gopenpgp` (tag `v2.8.1-passforios`) using `scripts/gopenpgp_build.sh`.

### Data Flow

Password data flows through:
1. Git repository sync (objective-git-swift-package)
2. Core Data persistence (passKit/pass.xcdatamodeld)
3. PGP encryption/decryption via PGPAgent
4. Keychain storage via KeychainAccess

## Testing

Tests use XCTest framework. Key test infrastructure:
- `passKitTests/Testbase/TestBase.swift` - Common test utilities and fixtures
- `passKitTests/Testbase/TestPGPKeys.swift` - Test PGP keys
- `passKitTests/Testbase/DictBasedKeychain.swift` - Mock keychain for tests

Run a single test file in Xcode by clicking the diamond next to the test class or method.

## Dependencies

All dependencies managed via Swift Package Manager (no Podfile):
- **ObjectivePGP**, **GopenPGP** - PGP operations
- **objective-git-swift-package** - Git operations
- **KeychainAccess** - Secure credential storage
- **OneTimePassword**, **Base32** - TOTP/HOTP
- **YubiKit** - Hardware security key support
- **SVProgressHUD** - UI progress indicators
- **FavIcon** - Website favicon extraction

## CI/CD

GitHub Actions with Fastlane:
- `testing.yml` - Runs on all pushes/PRs (macOS 15, Ruby 3.3, Go 1.23.x)
- `deploying.yml` - Deploys to TestFlight on master/release-* branches

Key Fastlane lanes: `test`, `beta`, `release`
