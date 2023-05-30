rule CommonBase64ReverseShellStrings {
	   meta:
      description = "Detects common powershell base64 reverse shell strings"
      date = "2023-05-30"
	  yarahub_reference_md5 = "bbb8305c576d51d2fce0e334424345f1"
	  yarahub_uuid = "fe6f0bba-18cd-483e-918e-51152058a5d1"
	  yarahub_license = "CC BY-NC-ND 4.0"
	  yarahub_rule_matching_tlp	= "TLP:WHITE"
	  yarahub_rule_sharing_tlp = "TLP:RED"
	  
   strings:
      $x01 = "BTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACg"
      $x02 = "GkAZQB4ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAo"
      $x03 = "GkAZQB4"
      $x04 = "bABpAGUAbgB0ACg"
      $x05 = "EcAZQB0AFMAdAByAGUAYQBtACg"
      $x06 = "BBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAo"
      $x07 = "AuAEcAZQB0AFMAdAByAGUAYQBtACg"
      $x08 = "BTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACg"
      
	  
   condition:
      2 of ($x*)
}
