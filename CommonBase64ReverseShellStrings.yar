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
      $x01 = "bABpAGUAbgB0ACgAIgA4ADUALgAyADEANwAuADEANwAwAC4"
	  
   condition:
      1 of ($x*)
}
