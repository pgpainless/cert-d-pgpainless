// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.cert_d.cli.PGPCertDCli;
import pgp.certificate_store.Certificate;
import picocli.CommandLine;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

@CommandLine.Command(name = "export",
        resourceBundle = "msg_export")
public class Export implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(Get.class);

    @Override
    public void run() {
        Iterator<Certificate> certificates = PGPCertDCli.getCertificateDirectory()
                .getCertificates();
        while (certificates.hasNext()) {
            try {
                Certificate certificate = certificates.next();
                InputStream inputStream = certificate.getInputStream();
                Streams.pipeAll(inputStream, System.out);
                inputStream.close();
            } catch (IOException e) {
                LOGGER.error("IO Error", e);
                System.exit(-1);
            }
        }
    }
}
