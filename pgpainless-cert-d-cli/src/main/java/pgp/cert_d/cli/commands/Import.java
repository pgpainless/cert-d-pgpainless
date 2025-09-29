// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.pgpainless.PGPainless;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.pgpainless.certificate_store.MergeCallbacks;
import pgp.cert_d.cli.PGPCertDCli;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.exception.BadDataException;
import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.IOException;

@CommandLine.Command(name = "import",
        resourceBundle = "msg_import")
public class Import implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(Import.class);

    @Override
    public void run() {
        try {
            java.util.List<OpenPGPCertificate> certsOrKeys = PGPainless.getInstance().readKey().parseKeysOrCertificates(System.in);
            for (OpenPGPCertificate toInsert : certsOrKeys) {
                try {
                    Certificate inserted = PGPCertDCli.getCertificateDirectory().insert(
                            new ByteArrayInputStream(toInsert.getEncoded()),
                            MergeCallbacks.mergeWithExisting());
                    LOGGER.info(inserted.getFingerprint());
                } catch (BadDataException e) {
                    LOGGER.error("Certificate " + toInsert.getKeyIdentifier() + " contains bad data.", e);
                } catch (IOException e) {
                    LOGGER.error("IO error importing certificate " + toInsert.getKeyIdentifier(), e);
                } catch (InterruptedException e) {
                    LOGGER.error("Thread interrupted while importing certificate " + toInsert.getKeyIdentifier(), e);
                    System.exit(1);
                }
            }
        } catch (IOException e) {
            LOGGER.error("IO-Error.", e);
            System.exit(1);
        }
    }
}
