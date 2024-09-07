rule crime_phantom_loader_dll
{
	meta:
	    description = "Detects PhantomLoader C/C++ DLL"
		author = "Mohamed Talaat and ANY.RUN MA team"
		date = "2024-17-8"
		type = "crimeware"
		hash1 = "BD3231011448B2D6A335032D11C12CAD"
		hash2 = "CA303668B5420C022EF9C78CE1F2BFB7"
	strings:
		$pdb_str = "C:\\vmagent_new\\bin\\joblist" ascii  
		$mov_5F5E100 = {(BF| 68 | C7 45 ??) 00 E1 F5 05}
        $call_payload = /\xFF\x55.\x68.{4}\xFF.{3}\x33\xC0.\x8B\xE5\x5D\xC3/s
        // $call_payload = { FF 55 ?? 68 [4] FF [3] 33 C0 ?? 8B E5 5D C3}
	condition:
	    (uint16(0) == 0x5A4D)
		and 2 of them 
}