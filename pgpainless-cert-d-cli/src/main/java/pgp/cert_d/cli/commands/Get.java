// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.util.ArmorUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.cert_d.SpecialNames;
import pgp.cert_d.cli.PGPCertDCli;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;
import picocli.CommandLine;

import java.io.IOException;
import java.util.NoSuchElementException;

@CommandLine.Command(name = "get",
        resourceBundle = "msg_get")
public class Get implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(Get.class);

    @CommandLine.Option(names = {"-a", "--armor"})
    boolean armor = false;

    @CommandLine.Parameters(
            paramLabel = "IDENTIFIER",
            arity = "1"
    )
    String identifer;

    @Override
    public void run() {
        try {
            KeyMaterial record;
            if (SpecialNames.lookupSpecialName(identifer) != null) {
                record = PGPCertDCli.getCertificateDirectory().getBySpecialName(identifer);
            } else {
                record = PGPCertDCli.getCertificateDirectory().getByFingerprint(identifer.toLowerCase());
            }
            if (record == null) {
                return;
            }

            if (armor) {
                PGPKeyRing keyRing = PGPainless.readKeyRing().keyRing(record.getInputStream());
                ArmoredOutputStream armorOut = ArmorUtils.toAsciiArmoredStream(keyRing, System.out);
                Streams.pipeAll(record.getInputStream(), armorOut);
                armorOut.close();
            } else {
                Streams.pipeAll(record.getInputStream(), System.out);
            }

        } catch (NoSuchElementException e) {
            LOGGER.debug("Certificate not found.", e);
        } catch (IOException e) {
            LOGGER.error("IO Error", e);
            System.exit(-1);
        } catch (BadDataException e) {
            LOGGER.error("Certificate file contains bad data.", e);
            System.exit(-1);
        } catch (BadNameException e) {
            LOGGER.error("Certificate fingerprint mismatch.", e);
            System.exit(-1);
        }
    }
}
