rule Mirai_ELF_PPC
{
    meta:
        description = "Detects Mirai ELF binaries for PowerPC architecture"
        author = "DetectHQ"
    strings:
        $mirai_str1 = "/bin/sh" ascii
        $mirai_str2 = "/dev/watchdog" ascii
        $mirai_str3 = "/proc/net/tcp" ascii
        $mirai_str4 = "/etc/resolv.conf" ascii
    condition:
        uint32(0) == 0x7f454c46 and // ELF magic
        filesize < 500KB and
        all of ($mirai_str*)
}