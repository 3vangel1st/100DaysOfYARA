rule nsis_invoking_payload_dll {
	meta:
		author = "Tillmann Werner"
		date = "2022-01-13"
		description = "detects NSIS bytecode that invokes a payload DLL via the System.dll plugin"

	strings:
		$call_dll_bytecode = {
			// initialize System.dll plugin
			05 00 00 00  ?? ?? ?? ??  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
			// extract payload dll
			14 00 00 00  91 00 00 05  ?? ?? ?? ??  ?? ?? ?? ??  ff ff ff ff  ff ff ff ff  ?? ?? ?? ??
			// set overwrite off
			0d 00 00 00  0d 00 00 00  00 00 00 00  01 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
			// push command string
			1f 00 00 00  ?? ?? ?? ??  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
			// invoke payload dll via System.dll
			2c 00 00 00  ?? ?? ?? ??  ?? ?? ?? ??  00 00 00 00  00 00 00 00  01 00 00 00  00 00 00 00
			// quit
			04 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
			// return
			01 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
		}

	condition:
		all of them
}
