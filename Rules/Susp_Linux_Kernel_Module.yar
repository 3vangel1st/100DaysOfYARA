import "elf"

rule SUSP_LINUX_KENEL_MODULE_00
{
    meta:
        OneHundredDaysOfYARA    = "13"
        author                  = "Conor Quigley <schrodinger@konundrum.org>"
        description             = "Hunting for suspicious Linux kernel modules."
        license                 = "BSD-2-Clause"
        created                 = "2022-01-13"
        version                 = "1.3"

    strings:
        // Required for LKM
        $m1 = "init_module"
        $m2 = "cleanup_module"

        // Various strings we don't expect to find in a Kernel module.
        // Adjust to purpose!
        $a1 = "unset"
        $a2 = "HISTFILE"

        $b1 = "LD_PRELOAD"

        $rc1 = "/etc/rc0.d"
        $rc2 = "/etc/rc1.d"
        $rc3 = "/etc/rc2.d"
        $rc4 = "/etc/rc3.d"
        $rc5 = "/etc/rc4.d"
        $rc6 = "/etc/rc5.d"
        $rc7 = "/etc/rc6.d"
        $rc8 = "/etc/rcS.d"
        $rc9 = "/etc/rc.local"

    condition:
        // ELF Header
        uint32(0) == 0x464c457f
        and any of ($m*)
        and for any symbol in elf.symtab : (
            symbol.name == "init_module"
            and symbol.type == elf.STT_FUNC
        )

        // Various matching conditions
        and (
            all of ($a*)
            or any of ($b*)
            or any of ($rc*)
        )

        // Limit to file size. The larger the file size I tend to find more false positives.
        and filesize < 5MB
}
