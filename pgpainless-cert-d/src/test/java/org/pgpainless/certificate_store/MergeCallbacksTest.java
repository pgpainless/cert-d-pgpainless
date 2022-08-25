// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialMerger;
import pgp.certificate_store.exception.BadDataException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

public class MergeCallbacksTest {

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 8E0F C503 D081 002A 2BC8  60A1 1CFC 3439 106D 1DD1\n" +
            "Comment: Marge Simpson <marge@simpson.tv>\n" +
            "\n" +
            "lFgEYwdeTxYJKwYBBAHaRw8BAQdA/culAZNfjpo8NyfJv9ggwUJBY/9Ps27wRzj1\n" +
            "3i5Y/akAAQCel3XRH2ERU2+6C4kJEb3YXNtbH3CHJhkP+co3JQBJygz0tCBNYXJn\n" +
            "ZSBTaW1wc29uIDxtYXJnZUBzaW1wc29uLnR2PoiPBBMWCgBBBQJjB15QCRAc/DQ5\n" +
            "EG0d0RYhBI4PxQPQgQAqK8hgoRz8NDkQbR3RAp4BApsBBRYCAwEABAsJCAcFFQoJ\n" +
            "CAsCmQEAAC34AP9jqFThNA0FeNxEEh+BKA/diGkxsAZaI0HscLeuoECOoAD9FjcO\n" +
            "1TtI0UjF1wvRAGuoL6PrgNQ/kAE++zyzaXlbDAKcXQRjB15QEgorBgEEAZdVAQUB\n" +
            "AQdAHQPnqtZwENOdLiD19wgjUpo/U0pJ4s/HCjgUQrFro38DAQgHAAD/VrXgi8fE\n" +
            "UUAVLn+C3GXCJV0CBnCvLvMn6QwDUIbi1sgQF4h1BBgWCgAdBQJjB15QAp4BApsM\n" +
            "BRYCAwEABAsJCAcFFQoJCAsACgkQHPw0ORBtHdGDdgD8DS1IyA0j4mnKPw93BLLn\n" +
            "Wkt6Tc8tEc1Yy3fddhaGXXMBAIMu6ww43TM2EdQM/2orh8MhDZaBdDnD4egQ1ES4\n" +
            "zxYJnFgEYwdeUBYJKwYBBAHaRw8BAQdAw/Pfecs1QEMAuTY8wGqEgpigYFx6GLHS\n" +
            "qpgJkVds4hsAAP9JZ3XgkUguI4tUO9CyGCwxfBoUv1+F+XlYoxlyZV0M2A4qiNUE\n" +
            "GBYKAH0FAmMHXlACngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJjB15Q\n" +
            "AAoJEO8Ou9qRn4/Lk4ABAOTUMLOTPL9svmyoHmeVKYh4pL92/+zrsNL2Kh8BX7/F\n" +
            "APsE3/N3J5MB2ZEyzNSU84STG3Aqa+2I2u4w58CeL8eRCAAKCRAc/DQ5EG0d0QBm\n" +
            "AQDvHR1I/B4VBqMu44wcw1czqqFojv1KQMETnLCfU5Q4cwD+Mt6mNoXADACcnw2P\n" +
            "3u5u3NoFQ0v2vFSaCoBxVzUQrgo=\n" +
            "=OKv0\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String KEY_WITH_SIG = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 8E0F C503 D081 002A 2BC8  60A1 1CFC 3439 106D 1DD1\n" +
            "Comment: Marge Simpson <marge@simpson.tv>\n" +
            "\n" +
            "lFgEYwdeTxYJKwYBBAHaRw8BAQdA/culAZNfjpo8NyfJv9ggwUJBY/9Ps27wRzj1\n" +
            "3i5Y/akAAQCel3XRH2ERU2+6C4kJEb3YXNtbH3CHJhkP+co3JQBJygz0iHUEHxYK\n" +
            "ACcFAmMHXlAJEBz8NDkQbR3RFiEEjg/FA9CBACoryGChHPw0ORBtHdEAAEI4AP4w\n" +
            "H667enh2czzfH8n4NeluivHQIavx6THn40MELAiBQQD/T3IdrTn0YDVmfdAGmCPL\n" +
            "lNjOxPDus5SESpLuS6A7IAi0IE1hcmdlIFNpbXBzb24gPG1hcmdlQHNpbXBzb24u\n" +
            "dHY+iI8EExYKAEEFAmMHXlAJEBz8NDkQbR3RFiEEjg/FA9CBACoryGChHPw0ORBt\n" +
            "HdECngECmwEFFgIDAQAECwkIBwUVCgkICwKZAQAALfgA/2OoVOE0DQV43EQSH4Eo\n" +
            "D92IaTGwBlojQexwt66gQI6gAP0WNw7VO0jRSMXXC9EAa6gvo+uA1D+QAT77PLNp\n" +
            "eVsMApxdBGMHXlASCisGAQQBl1UBBQEBB0AdA+eq1nAQ050uIPX3CCNSmj9TSkni\n" +
            "z8cKOBRCsWujfwMBCAcAAP9WteCLx8RRQBUuf4LcZcIlXQIGcK8u8yfpDANQhuLW\n" +
            "yBAXiHUEGBYKAB0FAmMHXlACngECmwwFFgIDAQAECwkIBwUVCgkICwAKCRAc/DQ5\n" +
            "EG0d0YN2APwNLUjIDSPiaco/D3cEsudaS3pNzy0RzVjLd912FoZdcwEAgy7rDDjd\n" +
            "MzYR1Az/aiuHwyENloF0OcPh6BDURLjPFgmcWARjB15QFgkrBgEEAdpHDwEBB0DD\n" +
            "8995yzVAQwC5NjzAaoSCmKBgXHoYsdKqmAmRV2ziGwAA/0lndeCRSC4ji1Q70LIY\n" +
            "LDF8GhS/X4X5eVijGXJlXQzYDiqI1QQYFgoAfQUCYwdeUAKeAQKbAgUWAgMBAAQL\n" +
            "CQgHBRUKCQgLXyAEGRYKAAYFAmMHXlAACgkQ7w672pGfj8uTgAEA5NQws5M8v2y+\n" +
            "bKgeZ5UpiHikv3b/7Ouw0vYqHwFfv8UA+wTf83cnkwHZkTLM1JTzhJMbcCpr7Yja\n" +
            "7jDnwJ4vx5EIAAoJEBz8NDkQbR3RAGYBAO8dHUj8HhUGoy7jjBzDVzOqoWiO/UpA\n" +
            "wROcsJ9TlDhzAP4y3qY2hcAMAJyfDY/e7m7c2gVDS/a8VJoKgHFXNRCuCg==\n" +
            "=WrKH\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 8E0F C503 D081 002A 2BC8  60A1 1CFC 3439 106D 1DD1\n" +
            "Comment: Marge Simpson <marge@simpson.tv>\n" +
            "\n" +
            "mDMEYwdeTxYJKwYBBAHaRw8BAQdA/culAZNfjpo8NyfJv9ggwUJBY/9Ps27wRzj1\n" +
            "3i5Y/am0IE1hcmdlIFNpbXBzb24gPG1hcmdlQHNpbXBzb24udHY+iI8EExYKAEEF\n" +
            "AmMHXlAJEBz8NDkQbR3RFiEEjg/FA9CBACoryGChHPw0ORBtHdECngECmwEFFgID\n" +
            "AQAECwkIBwUVCgkICwKZAQAALfgA/2OoVOE0DQV43EQSH4EoD92IaTGwBlojQexw\n" +
            "t66gQI6gAP0WNw7VO0jRSMXXC9EAa6gvo+uA1D+QAT77PLNpeVsMArg4BGMHXlAS\n" +
            "CisGAQQBl1UBBQEBB0AdA+eq1nAQ050uIPX3CCNSmj9TSkniz8cKOBRCsWujfwMB\n" +
            "CAeIdQQYFgoAHQUCYwdeUAKeAQKbDAUWAgMBAAQLCQgHBRUKCQgLAAoJEBz8NDkQ\n" +
            "bR3Rg3YA/A0tSMgNI+Jpyj8PdwSy51pLek3PLRHNWMt33XYWhl1zAQCDLusMON0z\n" +
            "NhHUDP9qK4fDIQ2WgXQ5w+HoENREuM8WCbgzBGMHXlAWCSsGAQQB2kcPAQEHQMPz\n" +
            "33nLNUBDALk2PMBqhIKYoGBcehix0qqYCZFXbOIbiNUEGBYKAH0FAmMHXlACngEC\n" +
            "mwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJjB15QAAoJEO8Ou9qRn4/Lk4AB\n" +
            "AOTUMLOTPL9svmyoHmeVKYh4pL92/+zrsNL2Kh8BX7/FAPsE3/N3J5MB2ZEyzNSU\n" +
            "84STG3Aqa+2I2u4w58CeL8eRCAAKCRAc/DQ5EG0d0QBmAQDvHR1I/B4VBqMu44wc\n" +
            "w1czqqFojv1KQMETnLCfU5Q4cwD+Mt6mNoXADACcnw2P3u5u3NoFQ0v2vFSaCoBx\n" +
            "VzUQrgo=\n" +
            "=mKjW\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";
    private static final String CERT_WITH_SIG = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 8E0F C503 D081 002A 2BC8  60A1 1CFC 3439 106D 1DD1\n" +
            "Comment: Marge Simpson <marge@simpson.tv>\n" +
            "\n" +
            "mDMEYwdeTxYJKwYBBAHaRw8BAQdA/culAZNfjpo8NyfJv9ggwUJBY/9Ps27wRzj1\n" +
            "3i5Y/amIdQQfFgoAJwUCYwdeUAkQHPw0ORBtHdEWIQSOD8UD0IEAKivIYKEc/DQ5\n" +
            "EG0d0QAAQjgA/jAfrrt6eHZzPN8fyfg16W6K8dAhq/HpMefjQwQsCIFBAP9Pch2t\n" +
            "OfRgNWZ90AaYI8uU2M7E8O6zlIRKku5LoDsgCLQgTWFyZ2UgU2ltcHNvbiA8bWFy\n" +
            "Z2VAc2ltcHNvbi50dj6IjwQTFgoAQQUCYwdeUAkQHPw0ORBtHdEWIQSOD8UD0IEA\n" +
            "KivIYKEc/DQ5EG0d0QKeAQKbAQUWAgMBAAQLCQgHBRUKCQgLApkBAAAt+AD/Y6hU\n" +
            "4TQNBXjcRBIfgSgP3YhpMbAGWiNB7HC3rqBAjqAA/RY3DtU7SNFIxdcL0QBrqC+j\n" +
            "64DUP5ABPvs8s2l5WwwCuDgEYwdeUBIKKwYBBAGXVQEFAQEHQB0D56rWcBDTnS4g\n" +
            "9fcII1KaP1NKSeLPxwo4FEKxa6N/AwEIB4h1BBgWCgAdBQJjB15QAp4BApsMBRYC\n" +
            "AwEABAsJCAcFFQoJCAsACgkQHPw0ORBtHdGDdgD8DS1IyA0j4mnKPw93BLLnWkt6\n" +
            "Tc8tEc1Yy3fddhaGXXMBAIMu6ww43TM2EdQM/2orh8MhDZaBdDnD4egQ1ES4zxYJ\n" +
            "uDMEYwdeUBYJKwYBBAHaRw8BAQdAw/Pfecs1QEMAuTY8wGqEgpigYFx6GLHSqpgJ\n" +
            "kVds4huI1QQYFgoAfQUCYwdeUAKeAQKbAgUWAgMBAAQLCQgHBRUKCQgLXyAEGRYK\n" +
            "AAYFAmMHXlAACgkQ7w672pGfj8uTgAEA5NQws5M8v2y+bKgeZ5UpiHikv3b/7Ouw\n" +
            "0vYqHwFfv8UA+wTf83cnkwHZkTLM1JTzhJMbcCpr7Yja7jDnwJ4vx5EIAAoJEBz8\n" +
            "NDkQbR3RAGYBAO8dHUj8HhUGoy7jjBzDVzOqoWiO/UpAwROcsJ9TlDhzAP4y3qY2\n" +
            "hcAMAJyfDY/e7m7c2gVDS/a8VJoKgHFXNRCuCg==\n" +
            "=H6OY\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    private static final KeyMaterialReader reader = new KeyMaterialReader();

    @Test
    public void testOverrideExisting() throws IOException, BadDataException {
        KeyMaterialMerger merger = MergeCallbacks.overrideExisting();
        KeyMaterial existing = parse(CERT);
        KeyMaterial update = parse(KEY);

        assertSame(update, merger.merge(update, existing));
    }

    @Test
    public void testOverrideExistingNull() throws IOException, BadDataException {
        KeyMaterialMerger merger = MergeCallbacks.overrideExisting();
        KeyMaterial existing = null;
        KeyMaterial update = parse(KEY);

        assertSame(update, merger.merge(update, existing));
    }

    @Test
    public void testOverrideExistingWithNull() throws IOException, BadDataException {
        KeyMaterialMerger merger = MergeCallbacks.overrideExisting();
        KeyMaterial existing = parse(CERT);
        KeyMaterial update = null;

        assertNull(merger.merge(update, existing));
    }

    @Test
    public void testMergeExistingCertWithSelf() throws BadDataException, IOException {
        KeyMaterialMerger merger = MergeCallbacks.mergeWithExisting();
        KeyMaterial existing = parse(CERT);
        KeyMaterial update = parse(CERT);

        assertEncodingEquals(existing, merger.merge(update, existing));
    }

    @Test
    public void testMergeExistingCertWithNull() throws BadDataException, IOException {
        KeyMaterialMerger merger = MergeCallbacks.mergeWithExisting();
        KeyMaterial existing = parse(CERT);

        assertEncodingEquals(existing, merger.merge(null, existing));
    }


    @Test
    public void testMergeNullWithCert() throws BadDataException, IOException {
        KeyMaterialMerger merger = MergeCallbacks.mergeWithExisting();
        KeyMaterial update = parse(CERT);

        assertEncodingEquals(update, merger.merge(update, null));
    }

    @Test
    public void testMergeCertWithUpdate() throws BadDataException, IOException {
        KeyMaterialMerger merger = MergeCallbacks.mergeWithExisting();
        KeyMaterial existing = parse(CERT);
        KeyMaterial update = parse(CERT_WITH_SIG);

        assertEncodingEquals(update, merger.merge(update, existing));
    }

    @Test
    public void testMergeUpdateWithCert() throws BadDataException, IOException {
        KeyMaterialMerger merger = MergeCallbacks.mergeWithExisting();
        KeyMaterial existing = parse(CERT_WITH_SIG);
        KeyMaterial update = parse(CERT);

        assertEncodingEquals(existing, merger.merge(update, existing));
    }

    @Test
    public void testMergeKeyWithCert() throws BadDataException, IOException {
        KeyMaterialMerger merger = MergeCallbacks.mergeWithExisting();
        KeyMaterial existing = parse(KEY);
        KeyMaterial update = parse(CERT);

        assertEncodingEquals(existing, merger.merge(update, existing));
    }

    @Test
    public void testMergeCertWithKey() throws BadDataException, IOException {
        KeyMaterialMerger merger = MergeCallbacks.mergeWithExisting();
        KeyMaterial existing = parse(CERT);
        KeyMaterial update = parse(KEY);

        assertEncodingEquals(update, merger.merge(update, existing));
    }

    @Test
    public void testMergeKeyWithUpdateCert() throws BadDataException, IOException {
        KeyMaterialMerger merger = MergeCallbacks.mergeWithExisting();
        KeyMaterial existing = parse(KEY);
        KeyMaterial update = parse(CERT_WITH_SIG);
        KeyMaterial expected = parse(KEY_WITH_SIG);
        assertEncodingEquals(expected, merger.merge(update, existing));
    }

    @Test
    public void testMergeUpdateCertWithKey() throws BadDataException, IOException {
        KeyMaterialMerger merger = MergeCallbacks.mergeWithExisting();
        KeyMaterial existing = parse(CERT_WITH_SIG);
        KeyMaterial update = parse(KEY);
        KeyMaterial expected = parse(KEY_WITH_SIG);

        assertEncodingEquals(expected, merger.merge(update, existing));
    }

    private static KeyMaterial parse(String encoding) throws BadDataException, IOException {
        return reader.read(new ByteArrayInputStream(encoding.getBytes(Charset.forName("UTF8"))), null);
    }

    private static void assertEncodingEquals(KeyMaterial one, KeyMaterial two) throws IOException {
        ByteArrayOutputStream oneOut = new ByteArrayOutputStream();
        ByteArrayOutputStream twoOut = new ByteArrayOutputStream();

        Streams.pipeAll(one.getInputStream(), oneOut);
        Streams.pipeAll(two.getInputStream(), twoOut);

        assertArrayEquals(oneOut.toByteArray(), twoOut.toByteArray());
    }
}
