package org.pgpainless.certificate_store;

import org.junit.jupiter.api.Test;

public class CertificateAndKeyFactoryTest {

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

    @Test
    public void test() {
        
    }
}
