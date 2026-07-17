rule OceanLotus_SPECTRALVIPER_Generic {
    meta:
        description = "Detects SPECTRALVIPER/OceanLotus backdoor binaries based on strings and section names"
        author = "DetectHQ Threat Intelligence"
        reference = "https://detecthq.in"
    strings:
        $s1 = "viper" wide ascii
        $s2 = "Spectral" wide ascii
        $s3 = "Orchestrator" wide ascii
        $s4 = "FireAnt" wide ascii
        $s5 = "Metakit" wide ascii
    condition:
        (uint16(0) == 0x5A4D) and (1 of ($s*))
}