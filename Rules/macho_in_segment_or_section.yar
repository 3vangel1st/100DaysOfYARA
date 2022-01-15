import "macho"

rule macho_space_in_segment_or_section {
    meta:
        descrption = "Identify spaces in either a segment or section name of a Mach-o."
        author = "@shellcromancer <root@shellcromancer.io>"
        version = "0.1"
        date = "2022-01-08"
    condition:
        for any segment in macho.segments: (
            segment.segname contains " " or
            for any section in segment.sections: (
                section.sectname contains " "
            )
        )
}
