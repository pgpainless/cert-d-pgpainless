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
    public static KeyMaterialMerger mergeCertificates() {
        return new KeyMaterialMerger() {

            @Override
            public KeyMaterial merge(KeyMaterial data, KeyMaterial existing) throws IOException {
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
                        PGPPublicKeyRing existingCert = (PGPPublicKeyRing) existingKeyRing;
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
                    } else if (existingKeyRing instanceof PGPSecretKeyRing) {
                        PGPSecretKeyRing existingKey = (PGPSecretKeyRing) existingKeyRing;
                        PGPPublicKeyRing existingCert = PGPainless.extractCertificate(existingKey);
                        if (updatedKeyRing instanceof PGPPublicKeyRing) {
                            PGPPublicKeyRing updatedCert = (PGPPublicKeyRing) updatedKeyRing;
                            PGPPublicKeyRing mergedCert = PGPPublicKeyRing.join(existingCert, updatedCert);
                            mergedKeyRing = PGPSecretKeyRing.replacePublicKeys(existingKey, mergedCert);
                        } else if (updatedKeyRing instanceof PGPSecretKeyRing) {
                            PGPSecretKeyRing updatedKey = (PGPSecretKeyRing) updatedKeyRing;
                            if (!Arrays.equals(existingKey.getEncoded(), updatedKey.getEncoded())) {
                                // Merging secret keys is not supported.
                                return existing;
                            }
                            mergedKeyRing = existingKeyRing;
                        } else {
                            throw new IOException(new BadDataException());
                        }
                    } else {
                        throw new IOException(new BadDataException());
                    }

                    printOutDifferences(existingKeyRing, mergedKeyRing);

                    if (mergedKeyRing instanceof PGPPublicKeyRing) {
                        return CertificateFactory.certificateFromPublicKeyRing((PGPPublicKeyRing) mergedKeyRing, null);
                    } else {
                        return KeyFactory.keyFromSecretKeyRing((PGPSecretKeyRing) mergedKeyRing, null);
                    }

                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
            }

            private void printOutDifferences(PGPKeyRing existingCert, PGPKeyRing mergedCert) {
                int numSigsBefore = countSigs(existingCert);
                int numSigsAfter = countSigs(mergedCert);
                int newSigs = numSigsAfter - numSigsBefore;
                int numUidsBefore = count(existingCert.getPublicKey().getUserIDs());
                int numUidsAfter = count(mergedCert.getPublicKey().getUserIDs());
                int newUids = numUidsAfter - numUidsBefore;

                if (!existingCert.equals(mergedCert)) {
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

    /**
     * Return an implementation of {@link KeyMaterialMerger} that ignores the existing certificate and instead
     * returns the first instance.
     *
     * @return overriding callback
     */
    public static KeyMaterialMerger overrideCertificate() {
        // noinspection Convert2Lambda
        return new KeyMaterialMerger() {
            @Override
            public KeyMaterial merge(KeyMaterial data, KeyMaterial existing) {
                return data;
            }
        };
    }

    public static KeyMaterialMerger overrideKey() {
        // noinspection Convert2Lambda
        return new KeyMaterialMerger() {
            @Override
            public KeyMaterial merge(KeyMaterial data, KeyMaterial existing) {
                return data;
            }
        };
    }
}
