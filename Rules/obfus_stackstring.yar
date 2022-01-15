rule obfus_stackstring_imov {
    meta:
        descrption = "Identify stack-strings obfuscation via indirect moves."
        author = "@shellcromancer <root@shellcromancer.io>"
        version = "0.1"
        date = "2022-01-07"
        reference = "https://www.mandiant.com/resources/automatically-extracting-obfuscated-strings"
    strings:
        $mov_r = { c6 4? ?? 72 } // mov byte [rdi + ?], 0x72 ; 'r'
        $mov_s = { c6 4? 0? 73 } // mov byte [rdi + ?], 0x73 ; 's'
        $mov_t = { c6 4? 0? 74 } // mov byte [rdi + ?], 0x74 ; 't'
        $mov_l = { c6 4? 0? 6c } // mov byte [rdi + ?], 0x6c ; 'l'
        $mov_n = { c6 4? 0? 6e } // mov byte [rdi + ?], 0x6e ; 'n'
        $mov_e = { c6 4? 0? 65 } // mov byte [rdi + ?], 0x65 ; 'e'
        $mov_a = { c6 4? 0? 61 } // mov byte [rdi + ?], 0x61 ; 'a'
        $mov_o = { c6 4? 0? 6f } // mov byte [rdi + ?], 0x6f ; 'o'
        $mov_i = { c6 4? 0? 69 } // mov byte [rdi + ?], 0x79 ; 'i'

    condition:
        50% of them
}
