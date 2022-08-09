// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.cert_d.BadDataException;
import pgp.cert_d.BadNameException;
import pgp.cert_d.SpecialNames;
import pgp.cert_d.cli.PGPCertDCli;
import pgp.certificate.KeyMaterial;
import picocli.CommandLine;

import java.io.IOException;

@CommandLine.Command(name = "get",
        resourceBundle = "msg_get")
public class Get implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(Get.class);

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
                record = PGPCertDCli.getCertificateDirectory().getByFingerprint(identifer);
            }
            if (record == null) {
                return;
            }
            Streams.pipeAll(record.getInputStream(), System.out);
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
