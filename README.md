<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->
# Shared PGP Certificate Directory for Java

[![status-badge](https://ci.codeberg.org/api/badges/PGPainless/cert-d-pgpainless/status.svg)](https://ci.codeberg.org/PGPainless/cert-d-pgpainless)
[![Coverage Status](https://coveralls.io/repos/github/pgpainless/cert-d-pgpainless/badge.svg?branch=main)](https://coveralls.io/github/pgpainless/cert-d-pgpainless?branch=main)
[![REUSE status](https://api.reuse.software/badge/github.com/pgpainless/cert-d-pgpainless)](https://api.reuse.software/info/github.com/pgpainless/cert-d-pgpainless)

This repository contains implementations of the [Shared PGP Certificate Directory](https://sequoia-pgp.gitlab.io/pgp-cert-d/) specification using [PGPainless](https://pgpainless.org) as backend.

The module `pgpainless-cert-d` can be used as a drop-in implementation of
`pgp-certificate-store`.

The module `pgpainless-cert-d-cli` contains a command line application for
OpenPGP certificate management.
