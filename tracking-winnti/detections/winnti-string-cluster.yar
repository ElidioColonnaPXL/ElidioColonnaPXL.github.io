rule TGK_Winnti_Rootkit_String_Cluster
{
    meta:
        author = "The Guarded Kernel"
        description = "Research triage; not an attribution rule"
        reference = "https://www.lac.co.jp/lacwatch/report/20250213_004283.html"
    strings:
        $protocol = "IPSecMiniPort" wide
        $driver = "NDIS.SYS" ascii
        $beep = "\\Device\\Beep" wide
    condition:
        $protocol and $driver and $beep
}
