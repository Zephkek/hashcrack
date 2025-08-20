# HashCrack Platform TODO (Core Engine)

Scope: only `internal/hashes` and `internal/cracker`.

## Done
- internal/hashes
  - Hasher interface + `Params`
  - Algorithms: MD5, SHA1, SHA256/384/512, RIPEMD-160, NTLM, LM (full), MySQL 4.1+, LDAP {MD5}/{SHA}, bcrypt, scrypt, argon2id, Cisco7 compare
  - Registry (`Get`/`List`) and basic `Validate` + `Detect`
- internal/cracker
  - Wordlist cracker with worker pool, cancel, and progress
  - Simple rules (+u, +l, +c, +d1, +d2)
  - Event/log hook for UI or CLI

## In progress
- More unit tests and edge cases per algorithm
- Benchmarks for bcrypt, scrypt, argon2
- Cleaner error messages
- Actual Web server
- UI/UX

## Next
- Config for `Params` (env/file) with safe defaults
- Smoother progress updates for slow hashes
- Worker caps per algorithm
- Add PBKDF2 and SHA3
- Short docs and examples
- CI: lint and tests
