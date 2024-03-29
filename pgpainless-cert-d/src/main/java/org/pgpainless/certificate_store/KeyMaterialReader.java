// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialReaderBackend;
import pgp.certificate_store.exception.BadDataException;

import java.io.IOException;
import java.io.InputStream;

public class KeyMaterialReader implements KeyMaterialReaderBackend {

    @Override
    public KeyMaterial read(InputStream data, Long tag) throws IOException, BadDataException {
        PGPKeyRing keyMaterial;
        try {
            keyMaterial = PGPainless.readKeyRing().keyRing(data);
        } catch (IOException e) {
            String msg = e.getMessage();
            if (msg == null) {
                throw e;
            }
            if (msg.contains("unknown object in stream") ||
                    msg.contains("unexpected end of file in armored stream.") ||
                    msg.contains("invalid header encountered")) {
                throw new BadDataException();
            } else {
                throw e;
            }
        }
        if (keyMaterial instanceof PGPSecretKeyRing) {
            return KeyFactory.keyFromSecretKeyRing((PGPSecretKeyRing) keyMaterial, tag);
        } else if (keyMaterial instanceof PGPPublicKeyRing) {
            return CertificateFactory.certificateFromPublicKeyRing((PGPPublicKeyRing) keyMaterial, tag);
        } else {
            throw new BadDataException();
        }
    }
}
