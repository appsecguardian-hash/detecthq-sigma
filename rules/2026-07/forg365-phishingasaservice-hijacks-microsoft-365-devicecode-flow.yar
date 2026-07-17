rule Forg365_Microsoft_Login_Page {
    meta:
        description = "Detects the forged Microsoft device‑code login page used by Forg365"
        author = "DetectHQ"
        reference = "https://detecthq.in"
        date = "2026-07-13"
    strings:
        $title   = /<title>Microsoft account verification/i
        $form    = /<form[^>]*action=["']?https?:\/\/login\.microsoftonline\.com/i
        $script  = /atob\(['"][A-Za-z0-9+/=]+['"]\)/i   // base64‑obfuscated JS
        $css     = /font-family:\s*"Segoe UI"/i
    condition:
        all of ($title, $form) and $script
}