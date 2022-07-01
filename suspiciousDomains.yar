rule suspiciousDomains {

  meta:
      author = "Ian Bell"
      description = "Finds domains that I dont like the looks of"
      date = "2022-07-01"
      yarahub_author_twitter = "@ibell63"
      yarahub_reference_md5 = "88fa4d2323184e7227c1a70e1c0e79ec"
      yarahub_uuid = "ae1e8d0d-9f51-47d0-9b13-2767c4e73988"
      yarahub_license = "CC BY-NC 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"

  strings:
      $a0 = "l1vec4ms.com" nocase wide ascii

  condition:
      any of them
}
