import "pe"

rule crime_detect_ssload
{
    meta:
	    description = "Detects ssload (rust-based loader)"
		author = "Mohamed Talaat"
		date = "2024-18-8"
		type = "crimeware"
		hash1 = "E01DDD72BC81781FE86A68D3AD045548"
	strings:
	    $a1 = "/rustc/25ef9e3d85d934b27d9dada2f9dd52b1dc63bb04" ascii 
		$a2 = "AppData\\Local\\Temp\\tuHyNfOFXGWmy\\GsDSspC\\common\\src\\" ascii 
		$a3 = "POST*/*HTTP/1.1Content-Type: application/json" ascii 
		$hash_resolver = {BF 61 31 0A 00 8A 14 2B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 88 D6 80 C6 E0 80 FA 61 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C1 E0 05 ?? ?? ?? ?? ?? 01 C7}
	    
	condition:
	    (uint16(0) == 0x5A4D and 
		filesize < 500KB or
		pe.imphash() == "27CFE5237AF2563D5CF9261F92875077" and
		$hash_resolver and 
		any of ($a*)
		)

}