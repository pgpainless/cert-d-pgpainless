// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.encoders.Base64;
import org.pgpainless.PGPainless;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.Key;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class KeyFactory {

    public static Key keyFromSecretKeyRing(PGPSecretKeyRing secretKeyRing) {

        return new Key() {
            @Override
            public Certificate getCertificate() {
                PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeyRing);
                return CertificateFactory.certificateFromPublicKeyRing(publicKeys);
            }

            @Override
            public InputStream getInputStream() throws IOException {
                return new ByteArrayInputStream(secretKeyRing.getEncoded());
            }

            @Override
            public String getTag() throws IOException {
                MessageDigest digest;
                try {
                    digest = MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException e) {
                    throw new AssertionError("No MessageDigest for SHA-256 instantiated, although BC is on the classpath: " + e.getMessage());
                }
                digest.update(secretKeyRing.getEncoded());
                return Base64.toBase64String(digest.digest());
            }
        };
    }
}
