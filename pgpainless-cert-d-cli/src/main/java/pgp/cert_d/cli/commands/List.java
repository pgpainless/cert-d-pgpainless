// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import pgp.cert_d.cli.PGPCertDCli;
import pgp.certificate.Certificate;
import picocli.CommandLine;

import java.util.Iterator;

@CommandLine.Command(name = "list",
        resourceBundle = "msg_list"
)
public class List implements Runnable {

    @Override
    public void run() {
        Iterator<Certificate> certificates = PGPCertDCli.getCertificateDirectory()
                .items();
        while (certificates.hasNext()) {
            Certificate certificate = certificates.next();
            // CHECKSTYLE:OFF
            System.out.println(certificate.getFingerprint());
            // CHECKSTYLE:ON
        }
    }
}
