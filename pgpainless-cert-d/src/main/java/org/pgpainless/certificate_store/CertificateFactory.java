// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.pgpainless.key.OpenPgpFingerprint;
import pgp.certificate_store.certificate.Certificate;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

public class CertificateFactory {

    /**
     * Create a {@link Certificate} from the given {@link PGPPublicKeyRing} and tag.
     *
     * @param publicKeyRing PGPPublicKeyRing
     * @param tag tag
     * @return certificate
     * @throws IOException if the certificate cannot be encoded
     *
     * @deprecated use {@link #certificateFromOpenPGPCertificate(OpenPGPCertificate, Long)} instead.
     */
    @Deprecated
    public static Certificate certificateFromPublicKeyRing(PGPPublicKeyRing publicKeyRing, Long tag)
            throws IOException {
        byte[] bytes = publicKeyRing.getEncoded();
        String fingerprint = OpenPgpFingerprint.of(publicKeyRing).toString().toLowerCase();
        List<Long> subkeyIds = new ArrayList<>();
        Iterator<PGPPublicKey> keys = publicKeyRing.getPublicKeys();
        while (keys.hasNext()) {
            subkeyIds.add(keys.next().getKeyID());
        }

        return new Certificate(bytes, fingerprint, subkeyIds, tag);
    }

    /**
     * Create a {@link Certificate} from the given {@link OpenPGPCertificate} and tag.
     *
     * @param openPGPCertificate OpenPGPCertificate
     * @param tag tag
     * @return certificate
     * @throws IOException if the certificate cannot be encoded
     */
    public static Certificate certificateFromOpenPGPCertificate(OpenPGPCertificate openPGPCertificate, Long tag)
            throws IOException {
        byte[] bytes = openPGPCertificate.getEncoded(PacketFormat.ROUNDTRIP);
        String fingerprint = OpenPgpFingerprint.of(openPGPCertificate).getFingerprint().toLowerCase();
        List<Long> subkeyIds = openPGPCertificate.getValidKeys()
                .stream()
                .map(it -> it.getKeyIdentifier().getKeyId())
                .collect(Collectors.toList());
        return new Certificate(bytes, fingerprint, subkeyIds, tag);
    }
}
