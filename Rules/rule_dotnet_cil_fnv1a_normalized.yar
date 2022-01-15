rule dotnet_cil_fnv1a_normalized {
	meta:
		author = "Tillmann Werner"
		date = "2022-01-14"
		description = "normalized .NET CIL pattern for FNV1a hashing"

	strings:
		//  normalized bytecode pattern for the following high-level code:
		//	for (int i = 0; i < bytes.Length; i++)
		//	{
		//		byte b = bytes[i];
		//		num ^= b;
		//		num *= 0x100000001B3;
		//	}
		
		$loop_body_bytecode = {
			16				// ldc.i4.0
			(0a|0b|0c|0d)			// stloc.(0|1|2|3)
			2b 19				// br.s
			(06|07|08|09)			// ldloc.(0|1|2|3)
			(06|07|08|09)			// ldloc.(0|1|2|3)
			91				// ldelem.u1
			(0a|0b|0c|0d)			// stloc.(0|1|2|3)
			(06|07|08|09)			// ldloc.(0|1|2|3)
			(06|07|08|09)			// ldloc.(0|1|2|3)
			6E				// conv.u8
			61				// xor
			(0a|0b|0c|0d)			// stloc.(0|1|2|3)
			(06|07|08|09)			// ldloc.(0|1|2|3)
			21 B3 01 00 00 00 01 00 00	// ldc.i8 0x100000001B3
			5A				// mul
			(0a|0b|0c|0d)			// stloc.(0|1|2|3)
			(06|07|08|09)			// ldloc.(0|1|2|3)
			17				// ldc.i4.1
			58				// add
			(0a|0b|0c|0d)			// stloc.(0|1|2|3)
			(06|07|08|09)			// ldloc.(0|1|2|3)
			(06|07|08|09)			// ldloc.(0|1|2|3)
			8e				// ldlen
			69				// conv.i4
			32 e1				// blt.s
		}

	condition:
		all of them
}
