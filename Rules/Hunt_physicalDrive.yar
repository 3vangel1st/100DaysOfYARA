import "pe"
rule Toolmark_PhysicalDrive : TTP {
  meta:
    author = "smiller"
    description = "Looking for odd toolmarks, here a handle to raw disk MBR."
    DaysofYARA = "16/100"
    ref = "7F501AEB51CE3232A979CCF0E11278346F746D1F"
    ref = "902bcc27ed86bc623e20532239895da7"
    ref = "d1515a888defff96f724d49fe05bace85066f6eeafd81cd0d9c4c27fdebc9cbb"
  strings:
    $a = /\\\\\.\\PhysicalDrive\d/ nocase ascii wide // dont forget to escape the .
  condition:
    filesize < 25MB
    and uint16be(0) == 0x4d5a 
    and pe.number_of_signatures == 0
    and $a
}
rule Toolmark_PhysicalDrive_Catchall_Signed
{
   meta:
    ref = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
   strings:
    $a1 = "\\\\.\\PhysicalDrive%" ascii wide //variable
    $a2 = "\\\\\\\\.\\\\PhysicalDrive0" nocase ascii wide //hard-coded
    $b1 = /\\\\\.\\PhysicalDrive\d/ nocase ascii wide // dont forget to escape the .
    $b2 = /\\\\\\\\\.\\\\PhysicalDrive\d/ nocase ascii wide // dont forget to escape the .
    $PhysicalDrive_b64 = "PhysicalDrive" base64 base64wide
    $PhysicalDrive_xor = "PhysicalDrive" xor(0x01-0xff)
    $PhysicalDrive_flipflop = "hPsycilarDvie" nocase
    $PhysicalDrive_reverse = "evirDlacisyhP" nocase
    $PhysicalDrive_hex_enc_str = "506879736963616c4472697665" nocase
    $PhysicalDrive_fallchill = "PsbhrxaoDirev" nocase
    $PhysicalDrive_stackpush = "hehDrivhicalhPhys" nocase
    $PhysicalDrive_stackpushnull = "he\x00hDrivhicalhPhys"
    $PhysicalDrive_stackpushdoublenull = "he\x00\x00hDrivhicalhPhys"
    $PhysicalDrive_stackpushtriplenull = "he\x00\x00\x00hDrivhicalhPhys"
    $PhysicalDrive_smallStack = {c6(45|4424)??50 c6(45|4424)??68 c6(45|4424)??79 c6(45|4424)??73 c6(45|4424)??69 c6(45|4424)??63 c6(45|4424)??61 c6(45|4424)??6c c6(45|4424)??44 c6(45|4424)??72 c6(45|4424)??69 c6(45|4424)??76 c6(45|4424)??65}
    $PhysicalDrive_largeStack = {c7(45|85)[1-4]50000000 c7(45|85)[1-4]68000000 c7(45|85)[1-4]79000000 c7(45|85)[1-4]73000000 c7(45|85)[1-4]69000000 c7(45|85)[1-4]63000000 c7(45|85)[1-4]61000000 c7(45|85)[1-4]6c000000 c7(45|85)[1-4]44000000 c7(45|85)[1-4]72000000 c7(45|85)[1-4]69000000 c7(45|85)[1-4]76000000 c7(45|85)[1-4]65000000}
    $PhysicalDrive_register = {b?50000000 6689???? b?68000000 6689???? b?79000000 6689???? b?73000000 6689???? b?69000000 6689???? b?63000000 6689???? b?61000000 6689???? b?6c000000 6689???? b?44000000 6689???? b?72000000 6689???? b?69000000 6689???? b?76000000 6689???? b?65000000 6689????}
    $PhysicalDrive_dword = {c7(45|85)[1-4]73796850 c7(45|85)[1-4]6c616369 c7(45|85)[1-4]76697244 [0-1]c6(45|85)[1-4]65}
    $PhysicalDrive_pushpop = {6a505? 6a68 6689????5? 6a79 6689????5? 6a73 6689????5? 6a69 6689????5? 6a63 6689????5? 6a61 6689????5? 6a6c 6689????5? 6a44 6689????5? 6a72 6689????5? 6a69 6689????5? 6a76 6689????5?}
    $PhysicalDrive_callOverString = {e80d000000506879736963616c44726976655? }
   condition:
    any of them 
    and pe.number_of_signatures > 0
}
rule Toolmark_PhysicalDrive_Catchall_Unsigned
{
   meta:
    ref = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
   strings:
    $a1 = "\\\\.\\PhysicalDrive%" ascii wide //variable
    $a2 = "\\\\\\\\.\\\\PhysicalDrive0" nocase ascii wide //hard-coded
    $b1 = /\\\\\.\\PhysicalDrive\d/ nocase ascii wide // dont forget to escape the .
    $b2 = /\\\\\\\\\.\\\\PhysicalDrive\d/ nocase ascii wide // dont forget to escape the .
    $PhysicalDrive_b64 = "PhysicalDrive" base64 base64wide
    $PhysicalDrive_xor = "PhysicalDrive" xor(0x01-0xff)
    $PhysicalDrive_flipflop = "hPsycilarDvie" nocase
    $PhysicalDrive_reverse = "evirDlacisyhP" nocase
    $PhysicalDrive_hex_enc_str = "506879736963616c4472697665" nocase
    $PhysicalDrive_fallchill = "PsbhrxaoDirev" nocase
    $PhysicalDrive_stackpush = "hehDrivhicalhPhys" nocase
    $PhysicalDrive_stackpushnull = "he\x00hDrivhicalhPhys"
    $PhysicalDrive_stackpushdoublenull = "he\x00\x00hDrivhicalhPhys"
    $PhysicalDrive_stackpushtriplenull = "he\x00\x00\x00hDrivhicalhPhys"
    $PhysicalDrive_smallStack = {c6(45|4424)??50 c6(45|4424)??68 c6(45|4424)??79 c6(45|4424)??73 c6(45|4424)??69 c6(45|4424)??63 c6(45|4424)??61 c6(45|4424)??6c c6(45|4424)??44 c6(45|4424)??72 c6(45|4424)??69 c6(45|4424)??76 c6(45|4424)??65}
    $PhysicalDrive_largeStack = {c7(45|85)[1-4]50000000 c7(45|85)[1-4]68000000 c7(45|85)[1-4]79000000 c7(45|85)[1-4]73000000 c7(45|85)[1-4]69000000 c7(45|85)[1-4]63000000 c7(45|85)[1-4]61000000 c7(45|85)[1-4]6c000000 c7(45|85)[1-4]44000000 c7(45|85)[1-4]72000000 c7(45|85)[1-4]69000000 c7(45|85)[1-4]76000000 c7(45|85)[1-4]65000000}
    $PhysicalDrive_register = {b?50000000 6689???? b?68000000 6689???? b?79000000 6689???? b?73000000 6689???? b?69000000 6689???? b?63000000 6689???? b?61000000 6689???? b?6c000000 6689???? b?44000000 6689???? b?72000000 6689???? b?69000000 6689???? b?76000000 6689???? b?65000000 6689????}
    $PhysicalDrive_dword = {c7(45|85)[1-4]73796850 c7(45|85)[1-4]6c616369 c7(45|85)[1-4]76697244 [0-1]c6(45|85)[1-4]65}
    $PhysicalDrive_pushpop = {6a505? 6a68 6689????5? 6a79 6689????5? 6a73 6689????5? 6a69 6689????5? 6a63 6689????5? 6a61 6689????5? 6a6c 6689????5? 6a44 6689????5? 6a72 6689????5? 6a69 6689????5? 6a76 6689????5?}
    $PhysicalDrive_callOverString = {e80d000000506879736963616c44726976655? }
   condition:
    any of them 
    and pe.number_of_signatures == 0
}
rule Toolmark_PhysicalDrive_StackOnly_Unsigned
{
   meta:
    ref = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
   strings:
    $PhysicalDrive_stackpush = "hehDrivhicalhPhys" nocase
    $PhysicalDrive_stackpushnull = "he\x00hDrivhicalhPhys"
    $PhysicalDrive_stackpushdoublenull = "he\x00\x00hDrivhicalhPhys"
    $PhysicalDrive_stackpushtriplenull = "he\x00\x00\x00hDrivhicalhPhys"
    $PhysicalDrive_smallStack = {c6(45|4424)??50 c6(45|4424)??68 c6(45|4424)??79 c6(45|4424)??73 c6(45|4424)??69 c6(45|4424)??63 c6(45|4424)??61 c6(45|4424)??6c c6(45|4424)??44 c6(45|4424)??72 c6(45|4424)??69 c6(45|4424)??76 c6(45|4424)??65}
    $PhysicalDrive_largeStack = {c7(45|85)[1-4]50000000 c7(45|85)[1-4]68000000 c7(45|85)[1-4]79000000 c7(45|85)[1-4]73000000 c7(45|85)[1-4]69000000 c7(45|85)[1-4]63000000 c7(45|85)[1-4]61000000 c7(45|85)[1-4]6c000000 c7(45|85)[1-4]44000000 c7(45|85)[1-4]72000000 c7(45|85)[1-4]69000000 c7(45|85)[1-4]76000000 c7(45|85)[1-4]65000000}
    $PhysicalDrive_register = {b?50000000 6689???? b?68000000 6689???? b?79000000 6689???? b?73000000 6689???? b?69000000 6689???? b?63000000 6689???? b?61000000 6689???? b?6c000000 6689???? b?44000000 6689???? b?72000000 6689???? b?69000000 6689???? b?76000000 6689???? b?65000000 6689????}
    $PhysicalDrive_dword = {c7(45|85)[1-4]73796850 c7(45|85)[1-4]6c616369 c7(45|85)[1-4]76697244 [0-1]c6(45|85)[1-4]65}
    $PhysicalDrive_pushpop = {6a505? 6a68 6689????5? 6a79 6689????5? 6a73 6689????5? 6a69 6689????5? 6a63 6689????5? 6a61 6689????5? 6a6c 6689????5? 6a44 6689????5? 6a72 6689????5? 6a69 6689????5? 6a76 6689????5?}
    $PhysicalDrive_callOverString = {e80d000000506879736963616c44726976655? }
   condition:
    any of them 
    and pe.number_of_signatures == 0
}
rule Toolmark_PhysicalDrive_StackOnly_Signed
{
   meta:
    ref = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
   strings:
    $PhysicalDrive_stackpush = "hehDrivhicalhPhys" nocase
    $PhysicalDrive_stackpushnull = "he\x00hDrivhicalhPhys"
    $PhysicalDrive_stackpushdoublenull = "he\x00\x00hDrivhicalhPhys"
    $PhysicalDrive_stackpushtriplenull = "he\x00\x00\x00hDrivhicalhPhys"
    $PhysicalDrive_smallStack = {c6(45|4424)??50 c6(45|4424)??68 c6(45|4424)??79 c6(45|4424)??73 c6(45|4424)??69 c6(45|4424)??63 c6(45|4424)??61 c6(45|4424)??6c c6(45|4424)??44 c6(45|4424)??72 c6(45|4424)??69 c6(45|4424)??76 c6(45|4424)??65}
    $PhysicalDrive_largeStack = {c7(45|85)[1-4]50000000 c7(45|85)[1-4]68000000 c7(45|85)[1-4]79000000 c7(45|85)[1-4]73000000 c7(45|85)[1-4]69000000 c7(45|85)[1-4]63000000 c7(45|85)[1-4]61000000 c7(45|85)[1-4]6c000000 c7(45|85)[1-4]44000000 c7(45|85)[1-4]72000000 c7(45|85)[1-4]69000000 c7(45|85)[1-4]76000000 c7(45|85)[1-4]65000000}
    $PhysicalDrive_register = {b?50000000 6689???? b?68000000 6689???? b?79000000 6689???? b?73000000 6689???? b?69000000 6689???? b?63000000 6689???? b?61000000 6689???? b?6c000000 6689???? b?44000000 6689???? b?72000000 6689???? b?69000000 6689???? b?76000000 6689???? b?65000000 6689????}
    $PhysicalDrive_dword = {c7(45|85)[1-4]73796850 c7(45|85)[1-4]6c616369 c7(45|85)[1-4]76697244 [0-1]c6(45|85)[1-4]65}
    $PhysicalDrive_pushpop = {6a505? 6a68 6689????5? 6a79 6689????5? 6a73 6689????5? 6a69 6689????5? 6a63 6689????5? 6a61 6689????5? 6a6c 6689????5? 6a44 6689????5? 6a72 6689????5? 6a69 6689????5? 6a76 6689????5?}
    $PhysicalDrive_callOverString = {e80d000000506879736963616c44726976655? }
   condition:
    any of them 
    and pe.number_of_signatures > 0
}
rule Toolmark_PhysicalDrive_xor_Unsigned
{
   meta:
    ref = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
   strings:
    $PhysicalDrive_xor = "PhysicalDrive" xor(0x01-0xff)
   condition:
    any of them 
    and pe.number_of_signatures == 0
}
rule Toolmark_PhysicalDrive_xor_Signed
{
   meta:
    ref = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
   strings:
    $PhysicalDrive_xor = "PhysicalDrive" xor(0x01-0xff)
   condition:
    any of them 
    and pe.number_of_signatures > 0
}
