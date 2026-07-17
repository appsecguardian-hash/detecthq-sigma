rule ClearFake_Cloudflare_Payload
{
    meta:
        description = "Detects ClearFake payloads typically delivered via cloud hosting (Cloudflare Pages)"
        author = "DetectHQ"
        family = "ClearFake"
    strings:
        $a1 = "powershell.exe -ExecutionPolicy Bypass -EncodedCommand" ascii wide
        $a2 = "CurrentVersion\\Run" ascii wide
        $a3 = "window.location.href" ascii wide
        $a4 = "/?x=" ascii wide
    condition:
        2 of ($a*)
}