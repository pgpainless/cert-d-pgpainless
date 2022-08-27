// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.certificate_store.PGPainlessCertD;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.info.KeyInfo;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;
import pgp.cert_d.cli.InstantiateCLI;
import pgp.cert_d.cli.PGPCertDCli;
import pgp.certificate_store.certificate.Key;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.exception.BadDataException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SetupTest {

    private PGPainlessCertD store;

    @BeforeEach
    public void setup() {
        InstantiateCLI.setInMemoryStore();
        store = PGPCertDCli.getCertificateDirectory();
    }

    @AfterEach
    public void teardown() {
        InstantiateCLI.resetStore();
        store = null;
    }

    @Test
    public void testSetupGeneratesTrustRoot()
            throws BadDataException, IOException {
        assertThrows(NoSuchElementException.class, () -> store.getTrustRoot());

        PGPCertDCli.main(new String[] {"setup"});
        KeyMaterial trustRoot = store.getTrustRoot();
        assertNotNull(trustRoot);
        assertTrue(trustRoot instanceof Key);

        // Check that key has no password
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(trustRoot.getInputStream());
        assertTrue(KeyInfo.isDecrypted(secretKeys.getSecretKey()));
    }

    @Test
    public void testSetupWithPassword()
            throws BadDataException, IOException, PGPException {
        assertThrows(NoSuchElementException.class, () -> store.getTrustRoot());

        PGPCertDCli.main(new String[] {"setup", "--with-password", "sw0rdf1sh"});
        KeyMaterial trustRoot = store.getTrustRoot();
        assertNotNull(trustRoot);
        assertTrue(trustRoot instanceof Key);

        // Check that key is encrypted
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(trustRoot.getInputStream());
        assertTrue(KeyInfo.isEncrypted(secretKeys.getSecretKey()));
        // Check that password matches
        assertNotNull(UnlockSecretKey.unlockSecretKey(
                secretKeys.getSecretKey(), Passphrase.fromPassword("sw0rdf1sh")));
    }

    @Test
    public void testSetupImportFromStdin()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            BadDataException, IOException {
        assertThrows(NoSuchElementException.class, () -> store.getTrustRoot());

        PGPSecretKeyRing trustRoot = PGPainless.generateKeyRing()
                .modernKeyRing("trust-root");
        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(trustRoot);
        String armored = PGPainless.asciiArmor(trustRoot);
        ByteArrayInputStream trustRootIn = new ByteArrayInputStream(
                armored.getBytes(Charset.forName("UTF8")));

        InputStream originalStdin = System.in;
        System.setIn(trustRootIn);
        PGPCertDCli.main(new String[] {"setup", "--import-from-stdin"});
        System.setIn(originalStdin);

        KeyMaterial importedTrustRoot = store.getTrustRoot();
        assertEquals(fingerprint.toString().toLowerCase(), importedTrustRoot.getFingerprint());
    }

    @Test
    public void testSetupOverridesExistingTrustRoot()
            throws BadDataException, IOException {
        assertThrows(NoSuchElementException.class, () -> store.getTrustRoot());

        PGPCertDCli.main(new String[] {"setup"});
        KeyMaterial trustRoot = store.getTrustRoot();
        assertNotNull(trustRoot);
        String fingerprint = trustRoot.getFingerprint();

        // Override trust-root by calling setup again
        PGPCertDCli.main(new String[] {"setup"});
        trustRoot = store.getTrustRoot();
        assertNotNull(trustRoot);

        assertNotEquals(fingerprint, trustRoot.getFingerprint());
    }
}
