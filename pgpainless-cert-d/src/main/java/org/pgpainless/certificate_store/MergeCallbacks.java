// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.OpenPgpFingerprint;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialMerger;
import pgp.certificate_store.exception.BadDataException;

import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;

public class MergeCallbacks {

    /**
     * Return a {@link KeyMaterialMerger} that merges the two copies of the same certificate (same primary key) into one
     * combined certificate.
     *
     * @return merging callback
     */
    public static KeyMaterialMerger mergeWithExisting() {
        return new KeyMaterialMerger() {

            @Override
            public KeyMaterial merge(KeyMaterial data, KeyMaterial existing)
                    throws IOException {
                // Simple cases: one is null -> return other
                if (data == null) {
                    return existing;
                }
                if (existing == null) {
                    return data;
                }

                try {
                    PGPKeyRing existingKeyRing = PGPainless.readKeyRing().keyRing(existing.getInputStream());
                    PGPKeyRing updatedKeyRing = PGPainless.readKeyRing().keyRing(data.getInputStream());

                    PGPKeyRing mergedKeyRing;

                    if (existingKeyRing instanceof PGPPublicKeyRing) {
                        mergedKeyRing = mergeWithCert((PGPPublicKeyRing) existingKeyRing, updatedKeyRing);
                    } else if (existingKeyRing instanceof PGPSecretKeyRing) {
                        mergedKeyRing = mergeWithKey(existingKeyRing, updatedKeyRing);
                    } else {
                        throw new IOException(new BadDataException());
                    }

                    printOutDifferences(existingKeyRing, mergedKeyRing);

                    return toKeyMaterial(mergedKeyRing);

                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
            }

            private PGPKeyRing mergeWithCert(PGPPublicKeyRing existingKeyRing, PGPKeyRing updatedKeyRing)
                    throws PGPException, IOException {
                PGPKeyRing mergedKeyRing;
                PGPPublicKeyRing existingCert = existingKeyRing;
                if (updatedKeyRing instanceof PGPPublicKeyRing) {
                    mergedKeyRing = PGPPublicKeyRing.join(existingCert, (PGPPublicKeyRing) updatedKeyRing);
                } else if (updatedKeyRing instanceof PGPSecretKeyRing) {
                    PGPPublicKeyRing updatedPublicKeys = PGPainless.extractCertificate((PGPSecretKeyRing) updatedKeyRing);
                    PGPPublicKeyRing mergedPublicKeys = PGPPublicKeyRing.join(existingCert, updatedPublicKeys);
                    updatedKeyRing = PGPSecretKeyRing.replacePublicKeys((PGPSecretKeyRing) updatedKeyRing, mergedPublicKeys);
                    mergedKeyRing = updatedKeyRing;
                } else {
                    throw new IOException(new BadDataException());
                }
                return mergedKeyRing;
            }

            private PGPKeyRing mergeWithKey(PGPKeyRing existingKeyRing, PGPKeyRing updatedKeyRing)
                    throws PGPException, IOException {
                PGPKeyRing mergedKeyRing;
                PGPSecretKeyRing existingKey = (PGPSecretKeyRing) existingKeyRing;
                PGPPublicKeyRing existingCert = PGPainless.extractCertificate(existingKey);
                if (updatedKeyRing instanceof PGPPublicKeyRing) {
                    PGPPublicKeyRing updatedCert = (PGPPublicKeyRing) updatedKeyRing;
                    PGPPublicKeyRing mergedCert = PGPPublicKeyRing.join(existingCert, updatedCert);
                    mergedKeyRing = PGPSecretKeyRing.replacePublicKeys(existingKey, mergedCert);
                } else if (updatedKeyRing instanceof PGPSecretKeyRing) {
                    // Merging keys is not supported
                    mergedKeyRing = existingKeyRing;
                } else {
                    throw new IOException(new BadDataException());
                }
                return mergedKeyRing;
            }

            private KeyMaterial toKeyMaterial(PGPKeyRing mergedKeyRing)
                    throws IOException {
                if (mergedKeyRing instanceof PGPPublicKeyRing) {
                    return CertificateFactory.certificateFromPublicKeyRing((PGPPublicKeyRing) mergedKeyRing, null);
                } else {
                    return KeyFactory.keyFromSecretKeyRing((PGPSecretKeyRing) mergedKeyRing, null);
                }
            }

            private void printOutDifferences(PGPKeyRing existingCert, PGPKeyRing mergedCert) throws IOException {
                int numSigsBefore = countSigs(existingCert);
                int numSigsAfter = countSigs(mergedCert);
                int newSigs = numSigsAfter - numSigsBefore;
                int numUidsBefore = count(existingCert.getPublicKey().getUserIDs());
                int numUidsAfter = count(mergedCert.getPublicKey().getUserIDs());
                int newUids = numUidsAfter - numUidsBefore;

                if (!Arrays.equals(existingCert.getEncoded(), mergedCert.getEncoded())) {
                    OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(mergedCert);
                    StringBuilder sb = new StringBuilder();
                    sb.append(String.format("Certificate %s has", fingerprint));
                    if (newSigs != 0) {
                        sb.append(String.format(" %d new signatures", newSigs));
                    }
                    if (newUids != 0) {
                        if (newSigs != 0) {
                            sb.append(" and");
                        }
                        sb.append(String.format(" %d new UIDs", newUids));
                    }
                    if (newSigs == 0 && newUids == 0) {
                        sb.append(" changed");
                    }

                    // In this case it is okay to print to stdout, since we are a CLI app
                    // CHECKSTYLE:OFF
                    System.out.println(sb);
                    // CHECKSTYLE:ON
                }
            }

            private int countSigs(PGPKeyRing keys) {
                int numSigs = 0;
                Iterator<PGPPublicKey> iterator = keys.getPublicKeys();
                while (iterator.hasNext()) {
                    PGPPublicKey key = iterator.next();
                    numSigs += count(key.getSignatures());
                }
                return numSigs;
            }

            // TODO: Use CollectionUtils.count() once available
            private int count(Iterator<?> iterator) {
                int num = 0;
                while (iterator.hasNext()) {
                    iterator.next();
                    num++;
                }
                return num;
            }
        };
    }

    public static KeyMaterialMerger overrideExisting() {
        // noinspection Convert2Lambda
        return new KeyMaterialMerger() {
            @Override
            public KeyMaterial merge(KeyMaterial data, KeyMaterial existing) {
                return data;
            }
        };
    }
}
