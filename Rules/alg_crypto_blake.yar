rule alg_crypto_blake {
    meta:
        description = "Identify code/constants for the BLAKE2/3 hashing algorithm."
        author = "@shellcromancer <root@shellcromancer.io>"
        version = "0.1"
        date = "2022-01-11"
        reference = "https://en.wikipedia.org/wiki/BLAKE_(hash_function)"
        implementation = "https://cs.opensource.google/go/x/crypto/+/master:blake2b/blake2b_amd64.s"
    strings:
        // BLAKE2 uses the same IV as SHA-256 and BLAKE3 so matches should be investigated
        $iv0 = { 6a09e667 } // Frac(sqrt(2))
        $iv1 = { bb67ae85 } // Frac(sqrt(3))
        $iv2 = { 3c6ef372 } // Frac(sqrt(5))
        $iv3 = { a54ff53a } // Frac(sqrt(7))
        $iv4 = { 510e527f } // Frac(sqrt(11))
        $iv5 = { 9b05688c } // Frac(sqrt(13))
        $iv6 = { 1f83d9ab } // Frac(sqrt(17))
        $iv7 = { 5be0cd19 } // Frac(sqrt(19))

        // pre computed sigma constants
        $sig1 = { 00 02 04 06 01 03 05 07 08 0a 0c 0e 09 0b 0c 0f }
        $sig2 = { 0e 04 09 0d 0a 08 0f 06 01 00 0b 05 0c 02 07 03 }
    condition:
        4 of ($iv*) or 2 of ($sig*)
}
