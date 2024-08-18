rule crime_js_encoded_maldoc
{
    meta: 
        description = "Detects Jscript.encode JavaScript code that will drop PhantomLoader"
        author = "Mohamed Talaat"
        reference = ""
        date = "2024-17-8"
        type = "crimeware"
        hash1 = "EC7E26A81B6002C53854A1769AD427A6"
        hash2 = "3027ce79ed3be30f94d3a1d7de771843"
    strings:
        $a1 = "AUtoclose" ascii
        $a2 = "LoadXML" ascii 
        $a3 = "UserForm1" ascii 
        
        $b1= "CDATA[\x0d\x0a#@~^" ascii
        $b2 = "==^#~@" ascii
        
        $c1 = {2d 3b 54 5a 63}
        $c2 = {2d 21 54 21 57 46}
    
    condition:
        (uint32(0) == 0xe011cfd0 and uint32(4) == 0xe11ab1a1) and all of them

}