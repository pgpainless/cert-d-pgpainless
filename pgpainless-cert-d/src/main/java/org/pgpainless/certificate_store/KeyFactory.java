// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.certificate.Key;

import java.io.IOException;

public class KeyFactory {

    public static Key keyFromSecretKeyRing(PGPSecretKeyRing secretKeyRing, Long tag) throws IOException {
        byte[] bytes = secretKeyRing.getEncoded();
        PGPPublicKeyRing publicKeyRing = PGPainless.extractCertificate(secretKeyRing);
        Certificate certificate = CertificateFactory.certificateFromPublicKeyRing(publicKeyRing, tag);
        return new Key(bytes, certificate, tag);
    }
}
