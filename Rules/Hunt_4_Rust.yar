import "pe"
import "elf"

rule lang_rust {
    meta:
        desc = "Identify a Rust binary regardless of format (PE, Macho, ELF) or arch."
        author = "@shellcromancer"
        version = "1.0"
        last_modified = "2022.01.09"
    strings:
        $s1 = "_$LT$"   // https://github.com/rizinorg/rizin/blob/34d345d884a83d8fbf9f2dd0b6d9276f1bf0095c/librz/bin/bin_language.c#L13
        $s2 = "rustc/"  // compiler based paths
    condition:
        (
            pe.is_pe or 
            elf.type or
            uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca
        ) and any of them
}
