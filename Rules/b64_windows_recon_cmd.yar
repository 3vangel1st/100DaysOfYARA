rule b64_windows_recon_cmds
{
    meta:
        description = "Detects some Windows commands typically used by reconnaissance scripts, encoded using base64. Generated using InQuest Base64 Regular Expression Generator (https://labs.inquest.net/tools/yara/b64-regexp-generator)"
        author = "@instacyber"
        example_hash = "ec525d45a168c8baff8f80cfa8bab609f5a1b4ea3b2406870ab5cb02542b8297"
    strings:
        // systeminfo
        $systeminfo = /([\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx]zeXN0ZW1pbmZv|[\x2b\x2f-9A-Za-z][3HXn]N5c3RlbWluZm[\x2b\x2f89]|c3lzdGVtaW5mb[\x2b\x2f-9w-z])/

        // net user
        $net_user = /([\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx]uZXQgdXNlc[g-v]|bmV0IHVzZX[I-L]|[\x2b\x2f-9A-Za-z][2GWm]5ldCB1c2Vy)/

        // net user administrator
        $net_user_administrator = /([\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx]uZXQgdXNlciBhZG1pbmlzdHJhdG9y|bmV0IHVzZXIgYWRtaW5pc3RyYXRvc[g-v]|[\x2b\x2f-9A-Za-z][2GWm]5ldCB1c2VyIGFkbWluaXN0cmF0b3[I-L])/

        // net use
        $net_use = /([\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx]uZXQgdXNl|[\x2b\x2f-9A-Za-z][2GWm]5ldCB1c2[U-X]|bmV0IHVzZ[Q-Za-f])/

        // net share
        $net_share = /([\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx]uZXQgc2h{2}cm[U-X]|[\x2b\x2f-9A-Za-z][2GWm]5ldCBzaGFyZ[Q-Za-f]|bmV0IHNoYXJl)/

        // net view
        $net_view = /([\x2b\x2f-9A-Za-z][2GWm]5ldCB2aWV3|bmV0IHZpZX[c-f]|[\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx]uZXQgdml{2}d[\x2b\x2f-9w-z])/

        // netstat -nao
        $netstat_nao = /([\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx]uZXRzdGF0IC1uYW[\x2b\x2f89]|bmV0c3RhdCAtbmFv|[\x2b\x2f-9A-Za-z][2GWm]5ldHN0YXQgLW5hb[\x2b\x2f-9w-z])/

        // arp -a
        $arp_a = /([\x2b\x2f-9A-Za-z][2GWm]FycCAtY[Q-Za-f]|YXJwIC1h|[\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx]hcnAgLW[E-H])/

        // ipconfig /all
        $ipconfig_all = /(aXBjb25maWcgL2Fsb[A-P]|[\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx]pcGNvbmZpZyAvYWxs|[\x2b\x2f-9A-Za-z][2GWm]lwY29uZmlnIC9hbG[w-z])/

        // tasklist /fi
        $tasklist_fi = /([\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx]0YXNrbGlzdCAvZm[k-n]|[\x2b\x2f-9A-Za-z][3HXn]Rhc2tsaXN0IC9ma[Q-Za-f]|dGFza2xpc3QgL2Zp)/

        // tasklist /v
        $tasklist_v = /(dGFza2xpc3QgL3[YZab]|[\x2b\x2f-9A-Za-z][3HXn]Rhc2tsaXN0IC92|[\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx]0YXNrbGlzdCAvd[g-v])/

        // gpresult /z
        $gpresult_z = /([\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx]ncHJlc3VsdCAve[g-v]|Z3ByZXN1bHQgL3[o-r]|[\x2b\x2f-9A-Za-z][2GWm]dwcmVzdWx0IC96)/
    condition:
        any of them
}
