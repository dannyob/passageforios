<img src="icon/icon_round.png" width="76"/>

[![GitHub release](https://img.shields.io/github/release/dannyob/passageforios.svg)](https://github.com/dannyob/passageforios/releases)
[![Build Status](https://github.com/dannyob/passageforios/workflows/Deploying/badge.svg)](https://github.com/dannyob/passageforios/actions)

> [!WARNING]
> **This is a one-person, mostly vibe-coded fork** of the established upstream [Pass for iOS](https://github.com/mssun/passforios).
>
> It is intended for experimental use and preparation for upstreaming (which may never happen). **Use at your own risk!** Consider the implications of using an unaudited, unstable fork before relying on it, and be prepared to find bugs, raise issues, and  fix them yourself!

# Passage for iOS

[Passage](https://github.com/FiloSottile/passage) is a fork of the command line program Password Store. Password store uses PGP to encrypt; Passage uses the modern [age](https://age-encryption.org/) utility and is written by age's author, [Filippo Valsorda](https://filippo.io).

Similarly, [Passage for iOS](https://github.com/dannyob/passageforios) is a friendly fork of [Pass for iOS](https://github.com/mssun/passforios), an iOS frontend to Password Store written by [Mingshen Sun](https://mssun.me/). It can read and write either PGP or age-encrypted password stores.

# Passage for iOS's parent: Pass

The vast majority of Passage for iOS's code comes from
[Pass](https://github.com/mssun/passforios). My hope is that the changes here
can be upstreamed to Pass for iOS at some point. 

You can and should donate to support the original Pass here:
[![Donate](https://img.shields.io/badge/paypal-donate-blue.svg)](https://www.paypal.me/mssun).

## Features

- Compatible with the Password Store *and* Passage command line tools.
- View, copy, add, and edit password entries.
- Encrypt and decrypt password entries by PGP keys or by a age identities.
- Synchronize with your password Git repository.
- User-friendly interface: search, long press to copy, copy and open link, etc.
- Support one-time password tokens (two-factor authentication codes).
- AutoFill in Safari/Chrome and [supported apps](https://github.com/agilebits/onepassword-app-extension).
- [PGP only] Supports YubiKey.
- [Age-only] Supports re-encrypting to multiple recipients via an .age-recipients
  file in the root directory. Commits modifying .age-recipients must be SSH-signed
  by someone already in the previous .age-recipients list.

## Building Passage for iOS

1. Install Go: `brew install go`.
1. Run `./scripts/crypto_build.sh` to build the Crypto framework (includes PGP, age, and signature verification).
1. Open the `pass.xcodeproj` file in Xcode.
1. Build & Run.

## License

MIT
