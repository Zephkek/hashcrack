# HashCrack Platform TODO (Core Engine)

## Done
- internal/hashes
  - Hasher interface + `Params`
  - Algorithms: MD5, SHA1, SHA256/384/512, RIPEMD-160, NTLM, LM (full), MySQL 4.1+, LDAP {MD5}/{SHA}, bcrypt, scrypt, argon2id, Cisco7 compare
  - Registry (`Get`/`List`) and basic `Validate` + `Detect`
- internal/cracker
  - Wordlist cracker with worker pool, cancel, and progress
  - Simple rules (+u, +l, +c, +d1, +d2)
  - Event/log hook for UI or CLI
  - Attack methods backend
  - Actual Web server backend
  - CLI interface
  - UI
  - Add PBKDF2 and SHA3
  - Proper documentation / readme
  - Short docs and examples

## Next
- CI: lint and tests
