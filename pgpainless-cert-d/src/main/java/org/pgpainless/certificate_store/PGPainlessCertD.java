// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import pgp.cert_d.BaseDirectoryProvider;
import pgp.cert_d.backend.FileBasedCertificateDirectoryBackend;
import pgp.cert_d.backend.InMemoryCertificateDirectoryBackend;
import pgp.cert_d.PGPCertificateDirectory;
import pgp.cert_d.subkey_lookup.InMemorySubkeyLookup;
import pgp.cert_d.subkey_lookup.SubkeyLookup;
import pgp.cert_d.subkey_lookup.SubkeyLookupFactory;
import pgp.certificate_store.exception.NotAStoreException;

import java.io.File;

public class PGPainlessCertD extends PGPCertificateDirectory {

    private static final KeyMaterialReader keyMaterialReader = new KeyMaterialReader();

    public PGPainlessCertD(Backend backend, SubkeyLookup subkeyLookup) {
        super(backend, subkeyLookup);
    }

    public static PGPainlessCertD inMemory() {
        Backend backend = new InMemoryCertificateDirectoryBackend(keyMaterialReader);
        SubkeyLookup subkeyLookup = new InMemorySubkeyLookup();
        return new PGPainlessCertD(backend, subkeyLookup);
    }

    public static PGPainlessCertD fileBased(SubkeyLookupFactory subkeyLookupFactory)
            throws NotAStoreException {
        return fileBased(BaseDirectoryProvider.getDefaultBaseDir(), subkeyLookupFactory);
    }

    public static PGPainlessCertD fileBased(File baseDirectory, SubkeyLookupFactory subkeyLookupFactory)
            throws NotAStoreException {
        Backend backend = new FileBasedCertificateDirectoryBackend(baseDirectory, keyMaterialReader);
        SubkeyLookup subkeyLookup = subkeyLookupFactory.createFileBasedInstance(baseDirectory);
        return new PGPainlessCertD(backend, subkeyLookup);
    }
}
