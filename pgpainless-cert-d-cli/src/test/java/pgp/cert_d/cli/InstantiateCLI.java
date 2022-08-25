// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli;

import org.pgpainless.certificate_store.PGPainlessCertD;

public class InstantiateCLI {

    public static void resetStore() {
        PGPCertDCli.certificateDirectory = null;
    }

    public static void setInMemoryStore() {
        PGPCertDCli.certificateDirectory = PGPainlessCertD.inMemory();
    }
}
