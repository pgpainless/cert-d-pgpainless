<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <info@pgpainless.org>
SPDX-License-Identifier: CC0-1.0
-->

# Cert-D-PGPainless Changelog

# 0.2.1
- Bump `pgpainless-core` to `1.3.12`

## 0.2.0
- `get`: Apply `toLowerCase()` to fingerprints
- Use BCs `PGPPublicKeyRing.join(first, second)` method to properly merge certificates
- Implement storing of `trust-root` key
- Bump `cert-d-java` to `0.2.1`
- Changes to CLI
  - Add support for i18n using resource bundles
  - Rename `import` command to `insert`
  - Rename `multi-import` command to `import`
  - Add `export` command
  - Add basic `list` command
  - `get` command: Allow querying by special name
  - Add armor headers to output of `get` command

## 0.1.2
- Add name and description to main command
- Bump `pgpainless-core` to `1.2.1`
- Bump `cert-d-java` to `0.1.1`
- Bump `slf4j` to `1.7.36`
- Bump `logback` to `1.2.11`
- Bump `mockito` to `4.5.1`
- Bump `picocli` to `4.6.3`

## 0.1.1
- Bump `pgpainless-core` to 1.1.3

## 0.1.0
- Initial Release
