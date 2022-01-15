rule alg_crypto_crc32 {
    meta:
        descrption = "Identify constants in the CRC32 cryptographic algorithm."
        author = "@shellcromancer <root@shellcromancer.io>"
        version = "0.1"
        creation_date = "2022-01-06"
        reference = "https://en.wikipedia.org/wiki/Cyclic_redundancy_check#CRC-32_algorithm"
        reference = "http://www.woodmann.com/fravia/crctut1.htm"
        hash = "c4f370622b7c8da5247e78a22e04a7778bd6712dbb84a05e60136b8defca4eed"
        location = "0x00401b50"
    strings:
        // CRC32Table
        $c1 = { 00 00 00 00 96 30 07 77 2c 61 0e ee ba 51 09 99 19 c4 6d 07 8f f4 6a 70 }
    
        // TODO add more
    condition:
        any of them
}
