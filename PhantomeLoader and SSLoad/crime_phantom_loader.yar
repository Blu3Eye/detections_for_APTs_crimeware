rule crime_phantom_loader_dll
{
	meta:
	    description = "Detects PhantomLoader c/c++ DLL"
		author = "Mohamed Talaat"
		date = "2024-17-8"
		type = "crimeware"
		hash1 = "BD3231011448B2D6A335032D11C12CAD"
	strings:
		$a1 = "C:\\vmagent_new\\bin\\joblist\\317196\\out\\Release\\PatchUp" ascii 
		$a2 = "Local\\Q360LeakFix" ascii 
		$a3 = "rashReport.dll" ascii 
		$a4 = "I18N.dll" ascii 
		$a5 = "360TSCommon.dll" ascii 
	    $xor_key = {59 4b 66 50 6c 72 76 4c 70 30 3c 42 61 73 26 4A 3E 25 64 75 5a 4e 74 40 6c 00}
		$hex_offset = {38 5D 01 00}
	
	condition:
	    (uint16(0) == 0x5A4D)
		and $xor_key and $hex_offset
		and (any of ($a*))
}