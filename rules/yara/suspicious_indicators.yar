/*
 * CyberWatch Local YARA Rules
 * Controlled local signature matching for static file analysis.
 */

rule Suspicious_Webshell_PHP
{
    meta:
        description = "Detects common PHP webshell execution indicators"
        author = "CyberWatch Threat Intelligence"
        severity = "HIGH"
    strings:
        $p1 = "passthru(" ascii nocase
        $p2 = "shell_exec(" ascii nocase
        $p3 = "system($_" ascii nocase
        $p4 = "eval(base64_decode(" ascii nocase
        $p5 = "assert($_POST" ascii nocase
        $p6 = "gzinflate(base64_decode(" ascii nocase
    condition:
        2 of ($p*)
}

rule Suspicious_PowerShell_Downloader
{
    meta:
        description = "Detects PowerShell one-liner payload download and execution"
        author = "CyberWatch Threat Intelligence"
        severity = "HIGH"
    strings:
        $ps1 = "Net.WebClient" ascii nocase
        $ps2 = "DownloadString(" ascii nocase
        $ps3 = "DownloadFile(" ascii nocase
        $ps4 = "Invoke-Expression" ascii nocase
        $ps5 = "IEX(" ascii nocase
        $ps6 = "Start-BitsTransfer" ascii nocase
        $ps7 = "-EncodedCommand" ascii nocase
    condition:
        2 of ($ps*)
}

rule Suspicious_Ransomware_Note_Indicators
{
    meta:
        description = "Detects standard ransomware extortion notice patterns"
        author = "CyberWatch Threat Intelligence"
        severity = "CRITICAL"
    strings:
        $r1 = "all your files have been encrypted" ascii nocase
        $r2 = "your personal decryption key" ascii nocase
        $r3 = "send bitcoin to" ascii nocase
        $r4 = "decrypt your files" ascii nocase
        $r5 = "TOR browser" ascii nocase
        $r6 = ".onion" ascii nocase
    condition:
        3 of ($r*)
}

rule Suspicious_Evasion_Double_Extension
{
    meta:
        description = "Detects PE binary disguising with masqueraded document names"
        author = "CyberWatch Threat Intelligence"
        severity = "HIGH"
    strings:
        $mz = { 4D 5A }
        $ext1 = ".pdf.exe" ascii nocase
        $ext2 = ".docx.exe" ascii nocase
        $ext3 = ".xlsx.exe" ascii nocase
        $ext4 = ".jpg.exe" ascii nocase
    condition:
        $mz at 0 and (1 of ($ext*))
}
