// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.cert_d.cli.PGPCertDCli;
import pgp.certificate_store.certificate.Certificate;
import picocli.CommandLine;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

@CommandLine.Command(name = "export",
        resourceBundle = "msg_export")
public class Export implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(Export.class);

    @CommandLine.Option(names = {"-a", "--armor"})
    boolean armor = false;

    @Override
    public void run() {
        Iterator<Certificate> certificates = PGPCertDCli.getCertificateDirectory()
                .items();
        OutputStream out = armor ? new ArmoredOutputStream(System.out) : System.out;
        while (certificates.hasNext()) {
            try {
                Certificate certificate = certificates.next();
                InputStream inputStream = certificate.getInputStream();
                Streams.pipeAll(inputStream, out);
                inputStream.close();
            } catch (IOException e) {
                LOGGER.error("IO Error", e);
                System.exit(-1);
            }
        }
        if (armor) {
            try {
                out.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
