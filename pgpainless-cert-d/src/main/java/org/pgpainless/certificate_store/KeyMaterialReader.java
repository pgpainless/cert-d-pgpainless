// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.pgpainless.PGPainless;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialReaderBackend;
import pgp.certificate_store.exception.BadDataException;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public class KeyMaterialReader implements KeyMaterialReaderBackend {

    @Override
    public KeyMaterial read(InputStream data, Long tag) throws IOException, BadDataException {
        OpenPGPCertificate keyOrCertificate;
        try {
            keyOrCertificate = PGPainless.getInstance()
                    .readKey()
                    .parseCertificateOrKey(data);
        } catch (EOFException e) {
            // TODO: Pass 'e' once cert-d-java is bumped to 0.2.4
            throw new BadDataException();
        } catch (IOException e) {
            if (e.getMessage().contains("Neither a certificate, nor secret key.")) {
                throw new BadDataException();
            }
            throw e;
        }

        if (keyOrCertificate.isSecretKey()) {
            return KeyFactory.keyFromOpenPGPKey((OpenPGPKey) keyOrCertificate, tag);
        } else {
            return CertificateFactory.certificateFromOpenPGPCertificate(keyOrCertificate, tag);
        }
    }
}
