rule sus_esxcli_cmd {

meta: 
    author = "Ian Bell"
    description = "This rule detects files with suspicious VMware esxcli commands"
    date = "2024-10-11"
    yarahub_reference_md5 = "tbd"
    yarahub_uuid = "244c2030-fd17-4d4e-8836-d5bae7cb71d3"
    yarahub_license = "CC BY-NC 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"

strings:
	$s1 = "esxcli vm process kill"
	$s2 = "another string"
	
condition:
    (1 of them) or (all of them)

}  
