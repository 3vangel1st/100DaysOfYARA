rule hunt_PE_openssl_statically_compiled {
  meta:

        OneHundredDaysOfYARA    = "3/100"
        author                  = "Bartek Jerzman"
        description             = "Hunting for PE files with statically compile SSL library"
        vt_search               = "((content: \"\\openssl-x86-static-release\") or (content: \"\\openssl-x64-static-release\")) and type:peexe"

  strings:

        $openssl_x86 = "\\openssl-x86-static-release" ascii
        $openssl_x64 = "\\openssl-x64-static-release" ascii
   
  condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        any of ($openssl_*) 
}
