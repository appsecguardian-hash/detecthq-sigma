rule DeepSeek_BrowserRansomware_Python
{
    meta:
        description = "Detects DeepSeek LLM-generated Python browser-native ransomware leveraging File System Access API"
        author = "DetectHQ"
        reference = "VT:07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5"
    strings:
        $s1 = "Flask(__name__)" wide ascii
        $s2 = "request.files" wide ascii
        $s3 = "showDirectoryPicker" ascii
        $s4 = "showOpenFilePicker" ascii
        $s5 = "ransom note" ascii nocase
        $s6 = "encrypt" ascii
    condition:
        (filesize < 500KB) and 2 of ($s*)
}