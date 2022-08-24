// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.pgpainless.certificate_store.MergeCallbacks;
import pgp.cert_d.cli.PGPCertDCli;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.exception.BadDataException;
import picocli.CommandLine;

import java.io.IOException;

@CommandLine.Command(name = "insert",
        resourceBundle = "msg_insert")
public class Insert implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(Insert.class);

    @Override
    public void run() {
        try {
            Certificate certificate = PGPCertDCli.getCertificateDirectory()
                    .insert(System.in, MergeCallbacks.mergeCertificates());
        } catch (IOException e) {
            LOGGER.error("IO-Error.", e);
            System.exit(-1);
        } catch (InterruptedException e) {
            LOGGER.error("Thread interrupted.", e);
            System.exit(-1);
        } catch (BadDataException e) {
            LOGGER.error("Certificate contains bad data.", e);
            System.exit(-1);
        }
    }
}
