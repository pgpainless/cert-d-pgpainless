// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.pgpainless.key.OpenPgpFingerprint;
import pgp.certificate_store.certificate.Certificate;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class CertificateFactory {

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
}
