package hashes

import (
    "sort"
    "strings"
)

func Detect(target string) []string {
    t := strings.TrimSpace(target)
    if t == "" { return nil }

    order := []string{
        "ntlm", "md5", "lm",
        "sha1", "ripemd160",
        "mysql",
        "sha256", "sha384", "sha512",
        "sha3-224", "sha3-256", "sha3-384", "sha3-512",
        "shake128", "shake256",
        "cisco7", "ldap_md5", "ldap_sha1",
    }

    idx := map[string]int{}
    add := func(name string){ if _, ok := idx[name]; !ok { idx[name] = len(idx) } }

    lower := strings.ToLower(t)
    switch {
    case strings.HasPrefix(lower, "*$"):
        add("mysql")
    case strings.HasPrefix(lower, "*"):
        add("mysql")
    case strings.HasPrefix(t, "{MD5}"):
        add("ldap_md5")
    case strings.HasPrefix(t, "{SHA}"):
        add("ldap_sha1")
    }

    var matches []string
    for _, name := range order {
        ok, _ := Validate(name, t)
        if ok { matches = append(matches, name) }
    }

    for name := range idx {
        found := false
        for _, m := range matches { if m == name { found = true; break } }
        if !found { matches = append([]string{name}, matches...) }
    }

    rank := map[string]int{}
    for i, n := range order { rank[n] = i }
    sort.SliceStable(matches, func(i, j int) bool {
        ri, iok := rank[matches[i]]
        rj, jok := rank[matches[j]]
        if iok && jok { return ri < rj }
        if iok { return true }
        if jok { return false }
        return matches[i] < matches[j]
    })
    return matches
}
