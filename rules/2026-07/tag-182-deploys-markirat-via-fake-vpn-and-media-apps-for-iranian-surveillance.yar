rule MarkiRAT_TAG182_YESHICA_20260701 {
    meta:
        author = "DetectHQ by GanaSec"
        reference = "https://detecthq.in"
        date = "2026-07-01"
        description = "Detects MarkiRAT samples used by TAG-182, including YESHICA and Pis2ray VPN lures."
        malware_family = "MarkiRAT"
        threat_actor = "TAG-182"
    strings:
        $bits = "Background Intelligent Transfer Service" ascii wide
        $y1 = "YESHICA" ascii wide
        $y2 = "YEPlayer" ascii wide
        $p1 = "Pis2rayVPN" ascii wide
        $h1 = { 3B 17 22 81 F6 5C EA EE 28 0A E8 10 ED B6 FD 39 A1 EC D2 56 49 F9 29 F2 46 C0 40 5D F9 4F 4C 89 }
        $h2 = { 66 DC D9 8C 6B 31 0F 44 29 89 08 21 E6 09 D4 8C C6 39 5A 6B E1 5F FE 5A 12 1E C6 8B 7A 8F 74 02 }
        $h3 = { 51 A6 68 6B 8C 5E C7 C6 10 63 73 98 F3 DE 43 58 9F 4E 9F CB E8 BC C0 24 53 43 C5 45 4D 3B 91 DE }
        $h4 = { A4 F1 B7 9E 96 A7 D0 16 DE 19 91 A6 45 06 79 20 18 DE 99 EA C5 DF 00 F7 CA BE 26 EF 41 B2 BD 81 }
        $h5 = { 40 0E B6 A9 48 10 32 3A 1F C5 F8 AB 31 C6 82 FE 76 5A AE C2 CC 61 B3 7C 31 D7 19 C7 E4 5C 9A 6C }
        $h6 = { 8A 7F 5C 85 33 DF 9E 51 B2 DA 7C C2 AE B5 2D 87 87 41 8E 49 15 57 7C C9 28 8B E1 E4 6D 19 45 C6 }
    condition:
        any of ($bits, $y1, $y2, $p1) and 1 of ($h1, $h2, $h3, $h4, $h5, $h6)
}