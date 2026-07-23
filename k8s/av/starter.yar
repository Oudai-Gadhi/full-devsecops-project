/*
    Example starter ruleset. Replace/extend with your own or a maintained
    feed (e.g. YARA-Forge, Neo23x0/signature-base) mounted via the same
    ConfigMap/volume mechanism.
*/

rule Suspicious_Double_Extension
{
    meta:
        description = "Flags files with double extensions commonly used to disguise executables"
        severity = "medium"
    strings:
        $a = ".pdf.exe" nocase
        $b = ".doc.exe" nocase
        $c = ".jpg.exe" nocase
        $d = ".xls.scr" nocase
    condition:
        any of them
}

rule Embedded_Powershell_EncodedCommand
{
    meta:
        description = "Detects obfuscated/encoded PowerShell invocation strings"
        severity = "high"
    strings:
        $a = "-EncodedCommand" nocase
        $b = "-enc " nocase
        $c = "FromBase64String" nocase
    condition:
        any of them
}

rule Generic_EICAR_Test_String
{
    meta:
        description = "Detects the EICAR antivirus test string (useful for pipeline testing)"
        severity = "info"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
