// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import org.pgpainless.key.OpenPgpFingerprint;
import pgp.cert_d.cli.PGPCertDCli;
import picocli.CommandLine;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Set;
import java.util.regex.Pattern;

@CommandLine.Command(name = "find",
        resourceBundle = "msg_find")
public class Find implements Runnable {

    private static final Pattern LONG_KEY_ID = Pattern.compile("^[0-9A-Fa-f]{16}$");

    @CommandLine.Parameters(
            paramLabel = "IDENTIFIER",
            arity = "1")
    String identifier;

    @Override
    public void run() {
        if (identifier == null) {
            throw new IllegalArgumentException("No subkey ID provided.");
        }
        identifier = identifier.trim();
        long subkeyId = 0;
        try {
            OpenPgpFingerprint fingerprint = OpenPgpFingerprint.parse(identifier);
            subkeyId = fingerprint.getKeyId();
        } catch (IllegalArgumentException e) {
            if (!LONG_KEY_ID.matcher(identifier).matches()) {
                throw new IllegalArgumentException("Provided long key-id does not match expected format. " +
                        "A long key-id consists of 16 hexadecimal characters.");
            }
            subkeyId =  new BigInteger(identifier, 16).longValue();
        }

        try {
            Set<String> fingerprints = PGPCertDCli.getCertificateDirectory()
                    .getCertificateFingerprintsForSubkeyId(subkeyId);
            for (String fingerprint : fingerprints) {
                // CHECKSTYLE:OFF
                System.out.println(fingerprint);
                // CHECKSTYLE:ON
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
