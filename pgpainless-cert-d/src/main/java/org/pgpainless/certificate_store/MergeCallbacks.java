// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.pgpainless.PGPainless;
import org.pgpainless.key.OpenPgpFingerprint;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialMerger;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

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

                PGPainless api = PGPainless.getInstance();

                OpenPGPCertificate existingCert = api.readKey().parseCertificateOrKey(existing.getInputStream());
                OpenPGPCertificate updatedCert = api.readKey().parseCertificateOrKey(data.getInputStream());

                OpenPGPCertificate mergedCert = mergeCertificates(updatedCert, existingCert);

                printOutDifferences(existingCert, mergedCert);
                return toKeyMaterial(mergedCert);
            }

            private OpenPGPCertificate mergeCertificates(OpenPGPCertificate updatedCertOrKey,
                                                         OpenPGPCertificate existingCertOrKey) {
                if (!existingCertOrKey.getKeyIdentifier().matchesExplicit(updatedCertOrKey.getKeyIdentifier())) {
                    throw new IllegalArgumentException("Not the same OpenPGP key/certificate: Mismatched primary key.");
                }

                OpenPGPCertificate merged;

                try {
                    if (existingCertOrKey.isSecretKey()) {
                        OpenPGPKey existingKey = (OpenPGPKey) existingCertOrKey;

                        if (updatedCertOrKey.isSecretKey()) {
                            // Merge key with key
                            OpenPGPKey updatedKey = (OpenPGPKey) updatedCertOrKey;
                            OpenPGPCertificate mergedCertPart = OpenPGPCertificate.join(
                                    existingKey.toCertificate(),
                                    updatedKey.toCertificate());

                            List<PGPSecretKey> mergedSecretKeys = new ArrayList<>();
                            Iterator<PGPSecretKey> existingKeysIterator = existingKey.getPGPSecretKeyRing().getSecretKeys();
                            while (existingKeysIterator.hasNext()) {
                                mergedSecretKeys.add(existingKeysIterator.next());
                            }

                            Iterator<PGPSecretKey> updatedKeysIterator = updatedKey.getPGPSecretKeyRing().getSecretKeys();
                            while (updatedKeysIterator.hasNext()) {
                                PGPSecretKey next = updatedKeysIterator.next();
                                if (existingKey.getPGPSecretKeyRing().getSecretKey(next.getKeyIdentifier()) == null) {
                                    mergedSecretKeys.add(next);
                                }
                            }
                            PGPSecretKeyRing mergedSecretKeyRing = new PGPSecretKeyRing(mergedSecretKeys);
                            merged = new OpenPGPKey(
                                    PGPSecretKeyRing.replacePublicKeys(
                                            mergedSecretKeyRing,
                                            mergedCertPart.getPGPPublicKeyRing()));
                        } else {
                            // Merge key with cert
                            OpenPGPCertificate mergedCertPart = OpenPGPCertificate.join(
                                    existingKey.toCertificate(),
                                    updatedCertOrKey);
                            merged = new OpenPGPKey(
                                    PGPSecretKeyRing.replacePublicKeys(
                                            existingKey.getPGPSecretKeyRing(),
                                            mergedCertPart.getPGPPublicKeyRing()));
                        }
                    } else {
                        if (updatedCertOrKey.isSecretKey()) {
                            // Swap update and existing cert
                            return mergeCertificates(existingCertOrKey, updatedCertOrKey);
                        }

                        // Merge cert with cert
                        return OpenPGPCertificate.join(existingCertOrKey, updatedCertOrKey);
                    }

                    return merged;
                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
            }

            private KeyMaterial toKeyMaterial(OpenPGPCertificate mergedCertificate)
                    throws IOException {
                if (mergedCertificate.isSecretKey()) {
                    return KeyFactory.keyFromOpenPGPKey((OpenPGPKey) mergedCertificate, null);
                } else {
                    return CertificateFactory.certificateFromOpenPGPCertificate(mergedCertificate, null);
                }
            }

            private void printOutDifferences(OpenPGPCertificate existingCert, OpenPGPCertificate mergedCert) throws IOException {
                int numSigsBefore = countSigs(existingCert);
                int numSigsAfter = countSigs(mergedCert);
                int newSigs = numSigsAfter - numSigsBefore;
                int numUidsBefore = count(existingCert.getAllUserIds().iterator());
                int numUidsAfter = count(mergedCert.getAllUserIds().iterator());
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

            private int countSigs(OpenPGPCertificate keys) {
                int numSigs = 0;
                for (OpenPGPCertificate.OpenPGPComponentKey componentKey : keys.getKeys()) {
                    PGPPublicKey key = componentKey.getPGPPublicKey();
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
