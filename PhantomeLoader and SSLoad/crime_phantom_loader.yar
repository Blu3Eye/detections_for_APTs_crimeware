
rule crime_phantom_loader_dll

{
	meta:
		description = "Detects PhantomLoader C/C++ or Delphi"
		author = "Mohamed Talaat"
		date = "2024-17-8"
		type = "crimeware"
		hash1 = "BD3231011448B2D6A335032D11C12CAD"
		hash2 = "CA303668B5420C022EF9C78CE1F2BFB7"
		hash3 = "1D8D71B4A0870C0DFA3468470FB28A28"
		hash4 = "B28A478EB5B99EFCDC7CAF428BFFB89A"
	strings:
		// this string occurs in 3 of 4 
		$pdb_str = "C:\\vmagent_new\\bin\\joblist" ascii
		$iobit_str = "IUForceDelete123" ascii wide
		$mov_5F5E100 = { ( BF | 68 | C7 45 ?? ) 00 E1 F5 05 }
		$payload_size = { ( D0 | 6C ) 07 00 00 }
		$call_payload = { FF 55 ?? 68 [4] FF [-] 33 C0 ?? 8B E5 5D C3 }
	condition:
		(uint16(0) == 0x5A4D) and
		all of ($mov_5F5E100, $payload_size, $call_payload) and
		any of ($pdb_str, $iobit_str)
}
