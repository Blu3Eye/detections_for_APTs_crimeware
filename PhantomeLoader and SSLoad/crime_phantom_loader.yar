rule crime_phantom_loader_dll
{
	meta:
	    description = "Detects PhantomLoader C/C++ DLL"
		author = "Mohamed Talaat"
		date = "2024-17-8"
		type = "crimeware"
		hash1 = "BD3231011448B2D6A335032D11C12CAD"
	strings:
		$a1 = "C:\\vmagent_new\\bin\\joblist" ascii  
		//size of the buffer used to calculate the key index 
		$buffer_size = {00 E1 F5 05}
		$enc_code_size = {D0 07} 
	
	condition:
	    (uint16(0) == 0x5A4D)
		and $buffer_size and 
		$enc_code_size
		and (any of ($a*))
}