// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import pgp.certificate_store.KeyMaterial;
import pgp.certificate_store.KeyReaderBackend;
import pgp.certificate_store.exception.BadDataException;

import java.io.IOException;
import java.io.InputStream;

public class KeyReader implements KeyReaderBackend {

    @Override
    public KeyMaterial read(InputStream data) throws IOException, BadDataException {
        final PGPKeyRing keyRing = PGPainless.readKeyRing().keyRing(data);
        if (keyRing instanceof PGPPublicKeyRing) {
            return CertificateFactory.certificateFromPublicKeyRing((PGPPublicKeyRing) keyRing);
        } else if (keyRing instanceof PGPSecretKeyRing) {
            return KeyFactory.keyFromSecretKeyRing((PGPSecretKeyRing) keyRing);
        } else {
            throw new BadDataException();
        }
    }
}
