// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import pgp.certificate_store.Key;
import pgp.certificate_store.KeyReaderBackend;
import pgp.certificate_store.exception.BadDataException;

import java.io.IOException;
import java.io.InputStream;

public class KeyReader implements KeyReaderBackend {

    @Override
    public Key readKey(InputStream data) throws IOException, BadDataException {
        final PGPSecretKeyRing key = PGPainless.readKeyRing().secretKeyRing(data);
        return KeyFactory.keyFromSecretKeyRing(key);
    }
}
