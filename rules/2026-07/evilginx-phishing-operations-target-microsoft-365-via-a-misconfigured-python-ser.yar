rule Evilginx_Fork_Detection {
    meta:
        description = "Detects Evilginx forks (red‑queen, black‑queen) and associated loader"
        author = "DetectHQ"
        reference = "https://github.com/kgretzky/evilginx2"
        date = "2026-07-13"
    strings:
        $binary_name = "evilginx2.exe" nocase
        $fork_red = "red-queen" nocase
        $fork_black = "black-queen" nocase
        $loader = "powershell.exe" nocase
        $task_name = "EvilProxy" nocase
    condition:
        any of ($binary_name, $fork_red, $fork_black) and $loader and $task_name
}