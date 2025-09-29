// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.junit.jupiter.api.Test;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.certificate.Key;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.exception.BadDataException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class KeyMaterialReaderTest {

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: B21A ABBF 15DF 0FDA 3742  4DE9 AD00 8384 AD0A 064C\n" +
            "Comment: Volodymyr Zelenskyy <zelenskyy@gov.ua>\n" +
            "\n" +
            "xVgEYwdKchYJKwYBBAHaRw8BAQdARSvx9BDpV0AoNYTmN/wrZXQAB7VzOV0rKEQc\n" +
            "OkhbP5wAAP0QE5FCIOvzea7wu3Yw3LDMmOOgMaWXngYp0948VPP2+xM7wsARBB8W\n" +
            "CgCDBYJjB0pyBYkFn6YAAwsJBwkQrQCDhK0KBkxHFAAAAAAAHgAgc2FsdEBub3Rh\n" +
            "dGlvbnMuc2VxdW9pYS1wZ3Aub3JnpqJFBi2xLa0V4D9k4rlmibhIsMRlcvK/MK83\n" +
            "Hjfh2CIDFQoIApsBAh4BFiEEshqrvxXfD9o3Qk3prQCDhK0KBkwAAIwNAP41uywA\n" +
            "z+qaRhWoj0stYmmefok4WHXk34jfameTopO1LAEA6L6/crPYzIcAZraaz0s5AM/2\n" +
            "OvJZR8LaBSj92uBDbAzNJlZvbG9keW15ciBaZWxlbnNreXkgPHplbGVuc2t5eUBn\n" +
            "b3YudWE+wsAUBBMWCgCGBYJjB0pyBYkFn6YAAwsJBwkQrQCDhK0KBkxHFAAAAAAA\n" +
            "HgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnuD/qrSefYHLBUQ70qQhb\n" +
            "cClzXkMQCoGO4S3WJzib/IADFQoIApkBApsBAh4BFiEEshqrvxXfD9o3Qk3prQCD\n" +
            "hK0KBkwAAL8DAP42+z1sDJlv64PW4iq2ODYcdY1NSptjzfiQ2hyodNBFpgD+Mkiv\n" +
            "9e2bFvlRj2Q5Brypy3ZwKvGtikUe3s+NlKMPlgTHWARjB0pyFgkrBgEEAdpHDwEB\n" +
            "B0BNjMb280vf8zNJ/YAtcc6nLe8uCSTtxKKHF0Go9kU+VgABAKTAn5oiixsRxfEb\n" +
            "k1I6WQbIGk/XNPZ241k65WRdg1qODvXCwMUEGBYKATcFgmMHSnIFiQWfpgAJEK0A\n" +
            "g4StCgZMRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ9el\n" +
            "oLUj9wUjbwI91PYFiLbcIMYw+G2w85rw5nLaXzHEApsCvqAEGRYKAG8FgmMHSnIJ\n" +
            "EDWWq2wLl0UaRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9y\n" +
            "Z622EwAZW4CP32L2ysCphw7DasyPOdBpDsiMv2LB7dz8FiEEZQkoZquL7+v7NBoA\n" +
            "NZarbAuXRRoAAOu3AP0X6dEVabI84d7t4AwRpmEiShSum9CJiODSs580lzkjlAD/\n" +
            "QOGSIE5iO155kPudwi8ubif+v4tXe4Ro++tIP85bTQ8WIQSyGqu/Fd8P2jdCTemt\n" +
            "AIOErQoGTAAAScwBAJ2A8vuK0wEMQHhVJR1lcjUaUm7EoBVuplF85dFipXjuAP40\n" +
            "bwvHajjg8wFLo8pwAATBd2gnNYXXDK7J2WwiZPAKAcddBGMHSnISCisGAQQBl1UB\n" +
            "BQEBB0DG0ue4giLkEecm/qz1wPQQBIl5v18/9M0SrMUk/M16agMBCAcAAP9Z4R+9\n" +
            "tmG3aUKOB9nwN1t4N1GnbYCmaZzTn3uJXLetYBFTwsAGBBgWCgB4BYJjB0pyBYkF\n" +
            "n6YACRCtAIOErQoGTEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBn\n" +
            "cC5vcmfZNJZA/uU2jCW1zQzCT9oK5hj0sL2taNvDFlLtkMCNqwKbDBYhBLIaq78V\n" +
            "3w/aN0JN6a0Ag4StCgZMAAAlKwD/eUEbC8MoIitKulDZawtlC0rSITXtQJqUkGNc\n" +
            "ujTPgIAA/1p/Y3sHn4nhmYcVX902BRXBp8YMD/cHQWZkWPhvM9YF\n" +
            "=3nhb\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    private static final String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: B21A ABBF 15DF 0FDA 3742  4DE9 AD00 8384 AD0A 064C\n" +
            "Comment: Volodymyr Zelenskyy <zelenskyy@gov.ua>\n" +
            "\n" +
            "xjMEYwdKchYJKwYBBAHaRw8BAQdARSvx9BDpV0AoNYTmN/wrZXQAB7VzOV0rKEQc\n" +
            "OkhbP5zCwBEEHxYKAIMFgmMHSnIFiQWfpgADCwkHCRCtAIOErQoGTEcUAAAAAAAe\n" +
            "ACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmemokUGLbEtrRXgP2TiuWaJ\n" +
            "uEiwxGVy8r8wrzceN+HYIgMVCggCmwECHgEWIQSyGqu/Fd8P2jdCTemtAIOErQoG\n" +
            "TAAAjA0A/jW7LADP6ppGFaiPSy1iaZ5+iThYdeTfiN9qZ5Oik7UsAQDovr9ys9jM\n" +
            "hwBmtprPSzkAz/Y68llHwtoFKP3a4ENsDM0mVm9sb2R5bXlyIFplbGVuc2t5eSA8\n" +
            "emVsZW5za3l5QGdvdi51YT7CwBQEExYKAIYFgmMHSnIFiQWfpgADCwkHCRCtAIOE\n" +
            "rQoGTEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcme4P+qt\n" +
            "J59gcsFRDvSpCFtwKXNeQxAKgY7hLdYnOJv8gAMVCggCmQECmwECHgEWIQSyGqu/\n" +
            "Fd8P2jdCTemtAIOErQoGTAAAvwMA/jb7PWwMmW/rg9biKrY4Nhx1jU1Km2PN+JDa\n" +
            "HKh00EWmAP4ySK/17ZsW+VGPZDkGvKnLdnAq8a2KRR7ez42Uow+WBM4zBGMHSnIW\n" +
            "CSsGAQQB2kcPAQEHQE2MxvbzS9/zM0n9gC1xzqct7y4JJO3EoocXQaj2RT5WwsDF\n" +
            "BBgWCgE3BYJjB0pyBYkFn6YACRCtAIOErQoGTEcUAAAAAAAeACBzYWx0QG5vdGF0\n" +
            "aW9ucy5zZXF1b2lhLXBncC5vcmfXpaC1I/cFI28CPdT2BYi23CDGMPhtsPOa8OZy\n" +
            "2l8xxAKbAr6gBBkWCgBvBYJjB0pyCRA1lqtsC5dFGkcUAAAAAAAeACBzYWx0QG5v\n" +
            "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmetthMAGVuAj99i9srAqYcOw2rMjznQaQ7I\n" +
            "jL9iwe3c/BYhBGUJKGari+/r+zQaADWWq2wLl0UaAADrtwD9F+nRFWmyPOHe7eAM\n" +
            "EaZhIkoUrpvQiYjg0rOfNJc5I5QA/0DhkiBOYjteeZD7ncIvLm4n/r+LV3uEaPvr\n" +
            "SD/OW00PFiEEshqrvxXfD9o3Qk3prQCDhK0KBkwAAEnMAQCdgPL7itMBDEB4VSUd\n" +
            "ZXI1GlJuxKAVbqZRfOXRYqV47gD+NG8Lx2o44PMBS6PKcAAEwXdoJzWF1wyuydls\n" +
            "ImTwCgHOOARjB0pyEgorBgEEAZdVAQUBAQdAxtLnuIIi5BHnJv6s9cD0EASJeb9f\n" +
            "P/TNEqzFJPzNemoDAQgHwsAGBBgWCgB4BYJjB0pyBYkFn6YACRCtAIOErQoGTEcU\n" +
            "AAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfZNJZA/uU2jCW1\n" +
            "zQzCT9oK5hj0sL2taNvDFlLtkMCNqwKbDBYhBLIaq78V3w/aN0JN6a0Ag4StCgZM\n" +
            "AAAlKwD/eUEbC8MoIitKulDZawtlC0rSITXtQJqUkGNcujTPgIAA/1p/Y3sHn4nh\n" +
            "mYcVX902BRXBp8YMD/cHQWZkWPhvM9YF\n" +
            "=o64m\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    private final KeyMaterialReader reader = new KeyMaterialReader();
    private final Charset UTF8 = StandardCharsets.UTF_8;

    @Test
    public void readBadDataTest() {
        assertThrows(BadDataException.class, () -> reader.read(
                new ByteArrayInputStream(CERT.substring(0, CERT.length() - 100).getBytes(UTF8)), null));
    }

    @Test
    public void readIncompleteDataTest() {
        assertThrows(BadDataException.class, () -> reader.read(
                new ByteArrayInputStream("ThisIsNotOpenPGPDataAtAllLol".getBytes(UTF8)), null));
    }

    @Test
    public void readKeyTest() throws BadDataException, IOException {
        KeyMaterial keyMaterial = reader.read(new ByteArrayInputStream(KEY.getBytes(UTF8)), 12L);
        assertNotNull(keyMaterial);
        assertTrue(keyMaterial instanceof Key);
        Key key = (Key) keyMaterial;
        assertEquals("b21aabbf15df0fda37424de9ad008384ad0a064c", key.getFingerprint());
        assertEquals(12L, key.getTag());
        Certificate certificate = key.getCertificate();
        assertEquals(key.getFingerprint(), certificate.getFingerprint());
        assertEquals(key.getTag(), certificate.getTag());
        assertEquals(key.getSubkeyIds(), certificate.getSubkeyIds());
    }

    @Test
    public void readCertTest() throws BadDataException, IOException {
        KeyMaterial keyMaterial = reader.read(new ByteArrayInputStream(CERT.getBytes(UTF8)), null);
        assertNotNull(keyMaterial);
        assertTrue(keyMaterial instanceof Certificate);
        Certificate certificate = (Certificate) keyMaterial;
        assertEquals("b21aabbf15df0fda37424de9ad008384ad0a064c", certificate.getFingerprint());
        assertNull(certificate.getTag());
        assertSame(certificate, certificate.asCertificate());
    }
}
