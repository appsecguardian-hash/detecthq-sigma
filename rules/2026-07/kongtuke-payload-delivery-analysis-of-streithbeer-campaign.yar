rule KongTuke_JS_StreithBeer
{
    meta:
        description = "Detects KongTuke JavaScript payload hosted on streith.beer"
        author = "DetectHQ"
        reference = "https://streith.beer/file.js"
        malware_family = "KongTuke"
    strings:
        $url1 = "streith.beer" ascii wide nocase
        $js1 = /window\.(location|open|setTimeout)/ nocase
        $obf1 = /eval\((atob|unescape|decodeURIComponent)\(/ nocase
    condition:
        uint8(0) == 0x2f and 1 of ($url*,$js1,$obf1)
}