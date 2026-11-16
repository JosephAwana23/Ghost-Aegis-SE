rule Windows_Encoded_PowerShell {
    meta:
        description = "Detects base64 encoded PowerShell execution flags"
        mitre_attack = "T1059.001"
        severity = "HIGH"
    strings:
        $enc1 = "-enc " ascii wide nocase
        $enc2 = "-EncodedCommand " ascii wide nocase
        $bypass = "ExecutionPolicy Bypass" ascii wide nocase
        $hidden = "-WindowStyle Hidden" ascii wide nocase
    condition:
        any of them
}

rule Suspicious_LOLBin_Execution {
    meta:
        description = "Detects Living-off-the-Land binaries used for payload staging"
        mitre_attack = "T1218"
        severity = "CRITICAL"
    strings:
        $certutil = "certutil -urlcache -split -f" ascii wide nocase
        $bitsadmin = "bitsadmin /transfer" ascii wide nocase
        $mshta = "mshta vbscript:" ascii wide nocase
        $regsvr = "regsvr32 /s /n /u /i:" ascii wide nocase
    condition:
        any of them
}

rule Ransomware_ShadowCopy_Inhibit {
    meta:
        description = "Detects deletion of Volume Shadow Copies and backup catalogs"
        mitre_attack = "T1490"
        severity = "CRITICAL"
    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "vssadmin.exe delete shadows" ascii wide nocase
        $wmic_sc = "shadowcopy delete" ascii wide nocase
        $wbadmin = "wbadmin delete catalog" ascii wide nocase
        $bcdedit = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
    condition:
        any of them
}

rule Credential_Dumping_Indicators {
    meta:
        description = "Detects LSASS memory dumping and SAM hive extraction"
        mitre_attack = "T1003.001"
        severity = "CRITICAL"
    strings:
        $sekurlsa = "sekurlsa::logonpasswords" ascii wide nocase
        $comsvcs = "comsvcs.dll, MiniDump" ascii wide nocase
        $procdump = "procdump -ma lsass" ascii wide nocase
        $reg_sam = "reg save HKLM\\SAM" ascii wide nocase
        $reg_sys = "reg save HKLM\\SYSTEM" ascii wide nocase
    condition:
        any of them
}

rule Suspicious_Persistence_Creation {
    meta:
        description = "Detects suspicious scheduled tasks and service creation commands"
        mitre_attack = "T1543.003"
        severity = "HIGH"
    strings:
        $sc_create = "sc create " ascii wide nocase
        $sc_bin = "binPath=" ascii wide nocase
        $schtasks = "schtasks /create /tn " ascii wide nocase
        $run_key = "CurrentVersion\\Run" ascii wide nocase
    condition:
        any of them
}
