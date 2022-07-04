// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli.commands;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.certificate_store.CertificateFactory;
import org.pgpainless.key.OpenPgpFingerprint;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.MergeCallback;

import java.io.IOException;
import java.util.Iterator;

public class DefaultMergeCallback implements MergeCallback {

    @Override
    public Certificate merge(Certificate data, Certificate existing) throws IOException {
        try {
            PGPPublicKeyRing existingCert = PGPainless.readKeyRing().publicKeyRing(existing.getInputStream());
            PGPPublicKeyRing updatedCert = PGPainless.readKeyRing().publicKeyRing(data.getInputStream());
            PGPPublicKeyRing mergedCert = PGPPublicKeyRing.join(existingCert, updatedCert);

            printOutDifferences(existingCert, mergedCert);

            return CertificateFactory.certificateFromPublicKeyRing(mergedCert);
        } catch (PGPException e) {
            throw new RuntimeException(e);
        }
    }

    private void printOutDifferences(PGPPublicKeyRing existingCert, PGPPublicKeyRing mergedCert) {
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

    private static int countSigs(PGPPublicKeyRing keys) {
        int numSigs = 0;
        for (PGPPublicKey key : keys) {
            numSigs += count(key.getSignatures());
        }
        return numSigs;
    }

    // TODO: Use CollectionUtils.count() once available
    private static int count(Iterator<?> iterator) {
        int num = 0;
        while (iterator.hasNext()) {
            iterator.next();
            num++;
        }
        return num;
    }
}
