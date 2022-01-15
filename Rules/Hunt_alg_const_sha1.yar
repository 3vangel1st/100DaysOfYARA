rule alg_crypto_sha1 {
    meta:
        description = "Identify constants for the SHA1 hashing algorithm."
        author = "@shellcromancer <root@shellcromancer.io>"
        version = "0.1"
        date = "2022-01-14"
        reference = "https://en.wikipedia.org/wiki/SHA-1"
        implementation = "https://cs.opensource.google/go/go/+/master:src/crypto/sha1/sha1block_amd64.s"
    strings:
        $init0 = { 67452301 }
        $init1 = { efcdcb89 }
        $init2 = { 98Badcfe }
        $init3 = { 10325476 }
        $init4 = { c3d2e1f0 }

        $k0 = { 5a827999 }
        $k1 = { 6ed9eba1 }
        $k2 = { 8f1bbcdc }
        $k3 = { ca62c1d6 }

    condition:
        2 of ($init*) or 2 of ($k*)
}
