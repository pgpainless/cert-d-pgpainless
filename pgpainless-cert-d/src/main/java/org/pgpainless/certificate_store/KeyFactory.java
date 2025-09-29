// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.pgpainless.PGPainless;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.certificate.Key;

import java.io.IOException;

public class KeyFactory {

    /**
     * Create a {@link Key} from the given {@link PGPSecretKeyRing} and tag.
     *
     * @param secretKeyRing PGPSecretKeyRing
     * @param tag tag
     * @return key
     * @throws IOException if the key cannot be encoded
     *
     * @deprecated use {@link #keyFromOpenPGPKey(OpenPGPKey, Long)} instead.
     */
    @Deprecated
    public static Key keyFromSecretKeyRing(PGPSecretKeyRing secretKeyRing, Long tag) throws IOException {
        byte[] bytes = secretKeyRing.getEncoded();
        PGPPublicKeyRing publicKeyRing = PGPainless.extractCertificate(secretKeyRing);
        Certificate certificate = CertificateFactory.certificateFromPublicKeyRing(publicKeyRing, tag);
        return new Key(bytes, certificate, tag);
    }

    /**
     * Create a {@link Key} from the given {@link OpenPGPKey} and tag.
     *
     * @param key OpenPGP key
     * @param tag tag
     * @return key
     * @throws IOException if the key cannot be encoded
     */
    public static Key keyFromOpenPGPKey(OpenPGPKey key, Long tag) throws IOException {
        byte[] bytes = key.getEncoded(PacketFormat.ROUNDTRIP);
        Certificate certificate = CertificateFactory.certificateFromOpenPGPCertificate(key.toCertificate(), tag);
        return new Key(bytes, certificate, tag);
    }
}
