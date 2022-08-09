// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import pgp.cert_d.BaseDirectoryProvider;
import pgp.cert_d.FileBasedCertificateDirectoryBackend;
import pgp.cert_d.InMemoryCertificateDirectoryBackend;
import pgp.cert_d.NotAStoreException;
import pgp.cert_d.PGPCertificateDirectory;

import java.io.File;

public class PGPainlessCertD extends PGPCertificateDirectory {

    private static final KeyMaterialReader keyMaterialReader = new KeyMaterialReader();

    public PGPainlessCertD(Backend backend) {
        super(backend);
    }

    public static PGPainlessCertD inMemory() {
        Backend backend = new InMemoryCertificateDirectoryBackend(keyMaterialReader);
        return new PGPainlessCertD(backend);
    }

    public static PGPainlessCertD fileBased() throws NotAStoreException {
        return fileBased(BaseDirectoryProvider.getDefaultBaseDir());
    }

    public static PGPainlessCertD fileBased(File baseDirectory) throws NotAStoreException {
        Backend backend = new FileBasedCertificateDirectoryBackend(baseDirectory, keyMaterialReader);
        return new PGPainlessCertD(backend);
    }
}
