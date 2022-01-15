rule alg_crypto_md5 {
    meta:
        description = "Identify code/constants for the MD5 hashing algorithm."
        author = "@shellcromancer <root@shellcromancer.io>"
        version = "0.1"
        date = "2022-01-11"
        reference = "https://en.wikipedia.org/wiki/MD5"
    strings:
        $cA = { 67452301 }
        $cB = { efcdab89 }
        $cC = { 98badcfe }
        $cD = { 10325476 }

        // K[i] := floor(232 × abs (sin(i + 1)))
        $k0 = { d76aa478 }
        $k1 = { e8c7b756 }
        $k2 = { 242070db }
        $k3 = { c1bdceee }
        $k4 = { f57c0faf }
        $k5 = { 4787c62a }
        $k6 = { a8304613 }
        $k7 = { fd469501 }
        $k63 = { fd469501 }
    condition:
        all of ($c*) or 4 of ($k*)
}
