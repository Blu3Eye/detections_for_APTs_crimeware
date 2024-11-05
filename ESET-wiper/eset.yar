
rule eset_1st_stage_dropper
{	meta:
	description = "Detects 1st stage dropper of the ESET wiper attack targeting israel"
	type = "Targeted"
	author = "Mohamed Talaat"
	date= "2024-11-5"
	hash = "1A94AA9F393B7D8391A64C68DDB28FEB"
	reference = "https://blu3eye.gitbook.io/malware-insight/eset-wiper"
	strings:
		$greeting = "Hey ESET, wait for the leak.. Doing business with the occupiers puts you in scope!" ascii nocase 
		$url = "www.oref.org" wide fullword
		//Saturday, October 07, 2023, 6:29:00 AM
		$hex_xor_key = {53 61 74 75 72 64 61 79 2C 20 4F 63 74 6F 62 6572 20 30 37 2C 20 32 30 32 33 2C 20 36 3A 32 39 3A 30 30}
		//$xor_key = "Saturday, October 07, 2023, 6:29:00 AM" ascii fullword
	condition:
		uint16(0) == 0x5a4d and 
		$hex_xor_key  and ($url or $greeting) 
}

rule eset_2nd_stage_wiper {
	meta:
		description = "Detects 2nd stage wiper of the ESET wiper attack targeting israel"
		type ="Targeted"
		author = "Mohamed Talaat"
		date = "2024-11-5"
		hash = "C99D1339030A80567E8004B44B9FF924"
		reference = "https://blu3eye.gitbook.io/malware-insight/eset-wiper"
	strings:
		$msg1 = "You can kill a people, but you can't kill an idea"
		$msg2 = "Resistance will continue until the final liberation of all Palestinian lands, and it is only a matter of time"
		$conf = "conf.conf"
		//$a1 = "Program Files (x86)" ascii fullword
		//$a2 = "ProgramData" ascii fullword
		$a3 = "Windows" ascii fullword
		//$a4 = "Program Files" ascii fullword
		//$a5 = "AppData" ascii fullword
		$a6 = "Users\\Public" ascii fullword
		////Saturday, October 07, 2023, 6:29:00 AM
		$hex_xor_key = {53 61 74 75 72 64 61 79 2C 20 4F 63 74 6F 62 6572 20 30 37 2C 20 32 30 32 33 2C 20 36 3A 32 39 3A 30 30}
		$cde_xor_loop = {C7 45 F4 26 00 00 00 33 D2 8D 0C 3E 8B C6 46 F7 75 F4 8A 82 ?? ?? ?? ?? 8B 55 FC 32 04 0A 88 01 3B F3 7C E3}
		//code pattern for LCG(Linear Congruential Generator)
		$cde_lcg = {55 8B EC 69 01 ?? ?? ?? ?? 33 D2 56 83 CE FF 05 ?? ?? ?? ?? F7 F6}
	condition:
		uint16(0) == 0x5a4d and $hex_xor_key and $cde_xor_loop and $cde_lcg and all of ($a*) and  $conf and  all of ($msg*)
}


rule MAL_Eset_Wiper_Nov24 {
    meta:
    description = "Detects 2nd stage of the ESET wiper attack targeting Israel"
    author = "Mohamed Talaat, Jonathan Peters"
    date = "2024-11-5"
    hash = "C99D1339030A80567E8004B44B9FF924"
    reference = "https://blu3eye.gitbook.io/malware-insight/eset-wiper"
    score = 80
    strings:
    $sa1 = "You can kill a people, but you can't kill an idea"
    $sa2 = "Resistance will continue until the final liberation of all Palestinian lands, and it is only a matter of time"
    $sa3 = "conf.conf"
    $sa4 = "Users\\Public" ascii fullword
    ////Saturday, October 07, 2023, 6:29:00 AM
    $p1 = {53 61 74 75 72 64 61 79 2C 20 4F 63 74 6F 62 6572 20 30 37 2C 20 32 30 32 33 2C 20 36 3A 32 39 3A 30 30} // hex_xor_key
    $p2 = {C7 45 F4 26 00 00 00 33 D2 8D 0C 3E 8B C6 46 F7 75 F4 8A 82 ?? ?? ?? ?? 8B 55 FC 32 04 0A 88 01 3B F3 7C E3} // cde_xor_loop
    //code pattern for LCG(Linear Congruential Generator)
    $p3= {55 8B EC 69 01 ?? ?? ?? ?? 33 D2 56 83 CE FF 05 ?? ?? ?? ?? F7 F6} // cde_lcg
    condition:
    uint16(0) == 0x5a4d and 
     all of ($p*) and 
     3 of ($sa*)
 }

