// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.util.Passphrase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.pgpainless.certificate_store.MergeCallbacks;
import pgp.cert_d.cli.PGPCertDCli;
import pgp.certificate_store.exception.BadDataException;
import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

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
        PGPSecretKeyRing trustRoot;
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
            PGPCertDCli.getCertificateDirectory().insertTrustRoot(inputStream, MergeCallbacks.overrideKey());

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

    private PGPSecretKeyRing generateTrustRoot(Passphrase passphrase) {
        PGPSecretKeyRing trustRoot;
        KeyRingBuilder builder = PGPainless.buildKeyRing()
                .addUserId("trust-root");
        if (passphrase != null) {
            builder.setPassphrase(passphrase);
        }
        builder.setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER));
        try {
        trustRoot = builder.build();
        } catch (NoSuchAlgorithmException | PGPException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Cannot generate trust-root OpenPGP key", e);
        }
        return trustRoot;
    }

    private PGPSecretKeyRing readTrustRoot(InputStream inputStream) {
        try {
            PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(inputStream);
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
