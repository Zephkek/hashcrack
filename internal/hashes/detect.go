package hashes

import (
    "regexp"
    "sort"
    "strings"
)

// Detect returns a ranked list of candidate algorithms for a given target string.
// It evaluates all registered algorithms using Validate() and then applies
// heuristic scoring to prioritize likely matches based on prefixes, length, and case.
func Detect(target string) []string {
    t := strings.TrimSpace(target)
    if t == "" { return nil }

    // Evaluate all registered algorithms
    algos := List()
    type cand struct{ name string; score int }
    candidates := []cand{}

    // Basic properties
    lower := strings.ToLower(t)
    upper := strings.ToUpper(t)
    isHex := reHex.MatchString(t)
    l := len(t)

    // Quick prefix heuristics
    hasPrefix := func(p string) bool { return strings.HasPrefix(lower, strings.ToLower(p)) }
    boost := map[string]int{}
    switch {
    case hasPrefix("$2a$") || hasPrefix("$2b$") || hasPrefix("$2y$"):
        boost["bcrypt"] += 60
    case hasPrefix("scrypt:"):
        boost["scrypt"] += 55
    case hasPrefix("argon2id:"):
        boost["argon2id"] += 55
    case hasPrefix("pbkdf2-"):
        boost["pbkdf2-sha1"] += 50; boost["pbkdf2-sha256"] += 50; boost["pbkdf2-sha512"] += 50
    }
    if hasPrefix("*") { boost["mysql"] += 40 }
    if strings.HasPrefix(t, "{MD5}") { boost["ldap_md5"] += 45 }
    if strings.HasPrefix(t, "{SHA}") { boost["ldap_sha1"] += 45 }
    if regexp.MustCompile(`^\d{2}[0-9A-Fa-f]{2,}$`).MatchString(t) { boost["cisco7"] += 40 }

    // Length/case-based hints for collisions
    if isHex {
        switch l {
        case 32:
            if t == upper {
                boost["ntlm"] += 30; boost["lm"] += 25; boost["md5"] += 10
            } else {
                boost["md5"] += 30; boost["ntlm"] += 10
            }
        case 40: boost["sha1"] += 25; boost["ripemd160"] += 15
        case 64: boost["sha256"] += 25
        case 96: boost["sha384"] += 20
        case 128: boost["sha512"] += 20
        }
    }

    // Validate and score
    for _, name := range algos {
        ok, _ := Validate(name, t)
        if !ok { continue }
        score := 10 // base score for any validator match
        if b, ok := boost[name]; ok { score += b }
        // Additional small nudges
        if strings.Contains(name, "sha3") && (l == 64 || l == 96 || l == 128) { score += 5 }
        if strings.Contains(name, "shake") && (l == 64 || l == 128) { score += 4 }
        candidates = append(candidates, cand{name, score})
    }

    if len(candidates) == 0 { return nil }

    sort.SliceStable(candidates, func(i, j int) bool {
        if candidates[i].score != candidates[j].score { return candidates[i].score > candidates[j].score }
        return candidates[i].name < candidates[j].name
    })

    out := make([]string, 0, len(candidates))
    seen := map[string]bool{}
    for _, c := range candidates {
        if !seen[c.name] { out = append(out, c.name); seen[c.name] = true }
    }
    return out
}
