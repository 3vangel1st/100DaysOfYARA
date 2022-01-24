private rule mbr {
  meta:
    author = "xorhex"
    OneHundredDaysOfYARA = "Day 8"
      
  condition:
      filesize == 512
    and
      uint16be(0x1fe) == 0x55aa
}

rule mbr_reset_disk_system {
  meta:
    author = "xorhex"
    reference ="https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=00h:_Reset_Disk_System"
    OneHundredDaysOfYARA = "Day 9"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb400
        )
      )
}

rule mbr_get_status_of_last_drive_operation {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=01h:_Get_Status_of_Last_Drive_Operation"
    OneHundredDaysOfYARA = "Day 9"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb401
        )
      )
}

rule mbr_read_sectors_from_drive : interesting {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=02h:_Read_Sectors_From_Drive"
    OneHundredDaysOfYARA = "Day 9"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb402
        )
      )
}

rule mbr_write_sectors_to_drive : interesting {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=03h:_Write_Sectors_To_Drive"
    OneHundredDaysOfYARA = "Day 9"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb403
        )
      )
}

rule mbr_verfiy_sectors_from_drive {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=04h:_Verify_Sectors_From_Drive"
    OneHundredDaysOfYARA = "Day 9"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb404
        )
      )
}

rule mbr_format_track : interesting {
  meta:
  author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=05h:_Format_Track"
    OneHundredDaysOfYARA = "Day 9"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb405
        )
      )
}

rule mbr_format_track_set_bad_sector_flags {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=06h:_Format_Track_Set_Bad_Sector_Flags"
    OneHundredDaysOfYARA = "Day 9"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb406
        )
      )
}

rule mbr_format_drive_starting_at_track : interesting {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=07h:_Format_Drive_Starting_at_Track"
    OneHundredDaysOfYARA = "Day 9"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb407
        )
      )
}

rule mbr_read_drive_parameters {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=08h:_Read_Drive_Parameters"
    OneHundredDaysOfYARA = "Day 9"
    
  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb408
        )
      )
}

rule mbr_init_drive_pair_characteristics {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=09h:_Init_Drive_Pair_Characteristics"
    OneHundredDaysOfYARA = "Day 9"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb409
        )
      )
}

rule mbr_read_long_sectors_from_drive {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=0Ah:_Read_Long_Sectors_From_Drive"
    OneHundredDaysOfYARA = "Day 10"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb40A
        )
      )
}

rule mbr_check_extensions_present {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=41h:_Check_Extensions_Present"
    OneHundredDaysOfYARA = "Day 10"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb441
        )
      )
}

rule mbr_extended_read_sectors_from_drive: interesting {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=42h:_Extended_Read_Sectors_From_Drive"
    OneHundredDaysOfYARA = "Day 10"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb442
        )
      )
}

rule mbr_extended_write_sectors_to_drive : interesting {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=43h:_Extended_Write_Sectors_to_Drive"
    OneHundredDaysOfYARA = "Day 10"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb443
        )
      )
}

rule mbr_extended_read_drive_parameters {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=48h:_Extended_Read_Drive_Parameters"
    OneHundredDaysOfYARA = "Day 10"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb448
        )
      )
}

rule mbr_get_drive_emulation_type {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_13H#INT_13h_AH=4Bh:_Get_Drive_Emulation_Type"
    OneHundredDaysOfYARA = "Day 10"

  strings:
    $int = { CD 13 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb44b
        )
      )
}

rule mbr_screen_write : interesting {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_10H"
    OneHundredDaysOfYARA = "Day 10"

  strings:
    $int = { CD 10 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb40e
        )
      )
}

rule mbr_write_graphics_pixel {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_10H"
    OneHundredDaysOfYARA = "Day 10"

  strings:
    $int = { CD 10 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb40c
        )
      )
}

rule mbr_write_character_only_at_cursor_position {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_10H"
    OneHundredDaysOfYARA = "Day 10"

  strings:
    $int = { CD 10 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb40a
        )
      )
}

rule mbr_write_character_and_attribute_only_at_cursor_position {
  meta:
    author = "xorhex"
    reference = "https://en.wikipedia.org/wiki/INT_10H"
    OneHundredDaysOfYARA = "Day 10"

  strings:
    $int = { CD 10 }
      
  condition:
      mbr
    and
      for any i in (1..#int) : (
        for any s in (1..30) : (
          uint16be(@int[i]-s) == 0xb409
        )
      )
}
