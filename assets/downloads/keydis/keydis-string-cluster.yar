import "pe"

rule TGK_KeyDis_Discord_String_Cluster
{
    meta:
        author = "The Guarded Kernel"
        description = "Static triage for the examined HTB KeyDis build"
        date = "2026-10-27"
        sample_sha256 = "caf4e182e31631bba63fcc17c30b8ec23cdd77147f445b01e1681d1830fe932f"
        reference = "https://theguardedkernel.be/articles/keydis/"
    strings:
        $s_endpoint = "/api/v10/channels/%s/messages" ascii
        $s_auth = "Authorization: Bot %s" ascii
        $s_key = "ADQI1G98G19FJ2IR31" ascii
        $s_block = "YEb NAts %zu: v0=0x%08x, v1=0x%08x" ascii
    condition:
        pe.is_pe and filesize < 200KB and all of ($s_*)
}
