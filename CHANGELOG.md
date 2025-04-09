# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.1]

### Uncategorized

- fix: MetaMask internal calls now specify `metamask` as origin ([#126](https://github.com/MetaMask/message-signing-snap/pull/126))

## [1.1.0]

### Added

- feat: add encryption capabilities ([#102](https://github.com/MetaMask/message-signing-snap/pull/102))

## [1.0.0]

### Changed

- **BREAKING** feat: generate unique entropy and keys for different origins ([#121](https://github.com/MetaMask/message-signing-snap/pull/121))
  > Public keys and signatures are domain-specific. The snap uses the origin of the request as a salt when generating entropy, which means the same user will have different public keys and signatures across different websites. This prevents cross-site correlation of user identities. However, MetaMask internal origins (like portfolio.metamask.io, docs.metamask.io, developer.metamask.io, and the extension itself) receive unsalted keys, allowing consistent identity across the MetaMask ecosystem.

### Fixed

- fix: use `entropySourceId` param when signing ([#120](https://github.com/MetaMask/message-signing-snap/pull/120))

## [0.7.0]

### Added

- feat: add `srpId` management ([#116](https://github.com/MetaMask/message-signing-snap/pull/116))

### Changed

- chore: update packages and sha ([#103](https://github.com/MetaMask/message-signing-snap/pull/103))

## [0.6.0]

### Changed

- refactor: move all `dependencies` to `devDependencies` ([#88](https://github.com/MetaMask/message-signing-snap/pull/88))
  - Since this is a preinstalled Snap, anything added to dependencies will end up in the client (extension and mobile) dependency-tree. Since Snaps bundle all of the dependencies required at runtime into one bundle.js file, these dependencies aren't used at runtime. Thus, we might as well reduce the size of the dependency-tree by moving the dependencies to be devDeps. This will ultimately help with the client node_modules sizing and dependency management

## [0.5.0]

### Added

- feat: update name and add more initial connections ([#86](https://github.com/MetaMask/message-signing-snap/pull/86))
- docs: add license ([#84](https://github.com/MetaMask/message-signing-snap/pull/84))
- build: update yarn and sha ([#85](https://github.com/MetaMask/message-signing-snap/pull/85))

## [0.4.0]

### Added

- feat: added portfolio automatic connection ([#82](https://github.com/MetaMask/message-signing-snap/pull/82))
- build: upgrade packages ([#81](https://github.com/MetaMask/message-signing-snap/pull/81))
- docs: add testing documentation for pre-installed snaps ([#80](https://github.com/MetaMask/message-signing-snap/pull/80))

## [0.3.3]

### Added

- fix: use correct bundle path for preinstalled snap ([#43](https://github.com/MetaMask/message-signing-snap/pull/43))

## [0.3.2]

### Added

- build: add preinstalled snap json for easier use in extension ([#41](https://github.com/MetaMask/message-signing-snap/pull/41))

## [0.3.1]

### Added

- build: add additional exports from package.json ([#37](https://github.com/MetaMask/message-signing-snap/pull/37))
- docs: Add audit report ([#27](https://github.com/MetaMask/message-signing-snap/pull/27))

## [0.3.0]

### Added

- Enabling MetaMask security code scanner ([#15](https://github.com/MetaMask/message-signing-snap/pull/15))
- refactor: update packages ([#25](https://github.com/MetaMask/message-signing-snap/pull/25))

## [0.2.0]

### Added

- Initial snap logic and tests.
- JSON-RPC docs & README.
- Update Snap Icon ([#1](https://github.com/MetaMask/message-signing-snap/pull/1))

[Unreleased]: https://github.com/MetaMask/message-signing-snap/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/MetaMask/message-signing-snap/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/MetaMask/message-signing-snap/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/MetaMask/message-signing-snap/compare/v0.7.0...v1.0.0
[0.7.0]: https://github.com/MetaMask/message-signing-snap/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/MetaMask/message-signing-snap/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/MetaMask/message-signing-snap/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/MetaMask/message-signing-snap/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/MetaMask/message-signing-snap/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/MetaMask/message-signing-snap/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/MetaMask/message-signing-snap/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/MetaMask/message-signing-snap/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/MetaMask/message-signing-snap/releases/tag/v0.2.0
