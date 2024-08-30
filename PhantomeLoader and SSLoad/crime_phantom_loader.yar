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
		$hex_offset = {38 5D 01 00}
	
	condition:
	    (uint16(0) == 0x5A4D)
		and $hex_offset
		and (any of ($a*))
}