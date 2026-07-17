rule CavernManticore_UxThemeDLL {
    meta:
        author = "DetectHQ by GanaSec"
        reference = "https://detecthq.in"
        date = "2026-07-07"
        description = "Detects Cavern Manticore's mixed-mode C++/CLI uxtheme.dll agent (backdoor)"
    strings:
        $mz = {4D 5A} // MZ header
        $dll_name = "uxtheme.dll"
        $mutex1 = "MYMUTEX123HELLP02"
        $mutex2 = "MYMUTEX123HELLP04"
        $export1 = "EnableThemeDialogTexture"
        $export_stub = {0F 0B} // ud2 padding in export stubs
    condition:
        $mz and $dll_name and ($mutex1 or $mutex2) and $export1 and $export_stub
}