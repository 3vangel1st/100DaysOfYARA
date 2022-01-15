  rule ARGS_socket_TCPIP {
  meta:
    author = "@notareverser"
    date = "2022-01-12"
    source = "https://twitter.com/notareverser/status/1481242024460312581"
  strings:
    /*
        6a06  push 6 ; IPPROTO_TCP
        6a01  push 1 ; SOCK_STREAM
        6a02  push 2 ; AF_INET
    */

    //  e8???? call rel16/32
    $c_rel = { 6a 06 6a 01 6a 02 e8 ?? ?? }
      
    // ff15???? call 
    $c_abs = { 6a 06 6a 01 6a 02 ff 15 ?? ?? }

    //  ffd?  call es?
    $c_reg = { 6a 06 6a 01 6a 02 ff d? }
  condition:
    any of them
}
