rule metasploit_shellcode_x86 {
    meta:
        descrption = "Identify pushed strings from metasploint x86 shellcode."
        author = "@shellcromancer <root@shellcromancer.io>"
        version = "0.1"
        date = "2022-01-10"
    strings:
        // https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/linux/ia32/single_adduser.asm#L48
        $pass1 = { 63 74 65 2f} // /etc
        $pass2 = { 61 70 2f 2f} // //pa
        $pass3 = { 64 77 73 73} // sswd

        // https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/linux/ia32/single_adduser.asm#L58
        $user = "ABC:AAnV3m35vbc/g:0:0::/:/bin/sh"

        // https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/linux/ia32/generic.asm#L94
        $sh1 = { 6e 69 62 2f} // /bin
        $sh2 = { 68 73 2f 2f} // //sh

        $flag1 = { 6f 6e 2d 2d } // --no
        $flag2 = { 74 69 64 65}  // edit
        $flag3 = { 6e 69}        // in g?

    condition:
        all of ($pass*) or 
        $user or 
        all of ($sh*) or
        all of ($flag*)
}
