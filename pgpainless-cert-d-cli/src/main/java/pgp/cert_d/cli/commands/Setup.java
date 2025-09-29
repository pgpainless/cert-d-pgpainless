// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.util.Passphrase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.pgpainless.certificate_store.MergeCallbacks;
import pgp.cert_d.cli.PGPCertDCli;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.exception.BadDataException;
import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

@CommandLine.Command(name = "setup",
        resourceBundle = "msg_setup")
public class Setup implements Runnable {

    public static final Logger LOGGER = LoggerFactory.getLogger(Setup.class);

    @CommandLine.ArgGroup()
    Exclusive exclusive;

    static class Exclusive {
        @CommandLine.Option(names = "--with-password",
                paramLabel = "PASSWORD")
        String password;

        @CommandLine.Option(names = "--import-from-stdin",
                description = "Import trust-root from stdin")
        boolean importFromStdin;
    }


    @Override
    public void run() {
        OpenPGPKey trustRoot;
        if (exclusive == null) {
            trustRoot = generateTrustRoot(Passphrase.emptyPassphrase());
        } else {
            if (exclusive.importFromStdin) {
                trustRoot = readTrustRoot(System.in);
            } else {
                trustRoot = generateTrustRoot(Passphrase.fromPassword(exclusive.password.trim()));
            }
        }

        try {
            InputStream inputStream = new ByteArrayInputStream(trustRoot.getEncoded());
            KeyMaterial inserted = PGPCertDCli.getCertificateDirectory()
                    .insertTrustRoot(inputStream, MergeCallbacks.overrideExisting());
            // CHECKSTYLE:OFF
            System.out.println(inserted.getFingerprint());
            // CHECKSTYLE:ON

        } catch (BadDataException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            LOGGER.error("IO error.", e);
            System.exit(-1);
        } catch (InterruptedException e) {
            LOGGER.error("Thread interrupted.", e);
            System.exit(-1);
        }
    }

    private OpenPGPKey generateTrustRoot(Passphrase passphrase) {
        OpenPGPKey trustRoot;
        KeyRingBuilder builder = PGPainless.getInstance().buildKey(OpenPGPKeyVersion.v4)
                .addUserId("trust-root");
        if (passphrase != null) {
            builder.setPassphrase(passphrase);
        }
        builder.setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER));
        trustRoot = builder.build();
        return trustRoot;
    }

    private OpenPGPKey readTrustRoot(InputStream inputStream) {
        try {
            OpenPGPKey secretKeys = PGPainless.getInstance().readKey().parseKey(inputStream);
            if (secretKeys == null) {
                throw new BadDataException();
            }
            return secretKeys;
        } catch (IOException e) {
            throw new RuntimeException("Cannot read trust-root OpenPGP key", e);
        } catch (BadDataException e) {
            throw new RuntimeException("trust-root does not contain OpenPGP key", e);
        }
    }
}
