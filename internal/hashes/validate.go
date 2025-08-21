package hashes

import (
	"encoding/base64"
	"regexp"
	"strings"
)

var (
	reHex      = regexp.MustCompile(`^[0-9a-fA-F]+$`) // hex lol
	reMySQL    = regexp.MustCompile(`^\*[A-F0-9]{40}$`) // https://passlib.readthedocs.io/en/stable/lib/passlib.hash.mysql41.html
	reLDAPmd5  = regexp.MustCompile(`^\{MD5\}[A-Za-z0-9+/=]+$`) // https://www.openldap.org/doc/admin24/security.html
	reLDAPsha1 = regexp.MustCompile(`^\{SHA\}[A-Za-z0-9+/=]+$`)// https://www.openldap.org/doc/admin24/security.html
	reCisco7   = regexp.MustCompile(`^\d{2}[0-9A-Fa-f]{2,}$`) //https://media.defense.gov/2022/Feb/17/2002940795/-1/-1/1/CSI_CISCO_PASSWORD_TYPES_BEST_PRACTICES_20220217.PDF
	reBcrypt   = regexp.MustCompile(`^\$2[aby]\$\d{2}\$`) // https://man.archlinux.org/man/crypt.5.en
	reScrypt   = regexp.MustCompile(`^scrypt:[0-9a-fA-F]+:[0-9a-fA-F]+$`) // https://hashcat.net/forum/archive/index.php?thread-8537.html=&utm_source=chatgpt.com
	reArgon2   = regexp.MustCompile(`^argon2id:[0-9a-fA-F]+:[0-9a-fA-F]+$`) // https://security.stackexchange.com/questions/222744/which-part-of-this-encoded-argon2-hash-is-the-salt
	rePBKDF2   = regexp.MustCompile(`^pbkdf2-(sha1|sha256|sha512):[0-9a-fA-F]+:\d+:[0-9a-fA-F]+$`) // pbkdf2-hash:salt:iter:key
)

func Validate(algo, target string) (bool, string) {
	t := strings.TrimSpace(target)
	a := strings.ToLower(strings.TrimSpace(algo))
	switch a {
	case "md5":
		if len(t) == 32 && reHex.MatchString(t) {
			if t == strings.ToUpper(t) {
				return true, "Note: 32-hex may also be NTLM/LM; confirm MD5 vs NTLM/LM"
			}
			return true, ""
		}
		return false, "MD5 must be 32 hex chars"
	case "sha1", "ripemd160":
		if len(t) == 40 && reHex.MatchString(t) { return true, "" }
		return false, a + " must be 40 hex chars"
	case "sha256":
		if len(t) == 64 && reHex.MatchString(t) { return true, "" }
		return false, "SHA256 must be 64 hex chars"
	case "sha384":
		if len(t) == 96 && reHex.MatchString(t) { return true, "" }
		return false, "SHA384 must be 96 hex chars"
	case "sha512":
		if len(t) == 128 && reHex.MatchString(t) { return true, "" }
		return false, "SHA512 must be 128 hex chars"
	case "sha3-224":
		if len(t) == 56 && reHex.MatchString(t) { return true, "" }
		return false, "SHA3-224 must be 56 hex chars"
	case "sha3-256":
		if len(t) == 64 && reHex.MatchString(t) { return true, "" }
		return false, "SHA3-256 must be 64 hex chars"
	case "sha3-384":
		if len(t) == 96 && reHex.MatchString(t) { return true, "" }
		return false, "SHA3-384 must be 96 hex chars"
	case "sha3-512":
		if len(t) == 128 && reHex.MatchString(t) { return true, "" }
		return false, "SHA3-512 must be 128 hex chars"
	case "shake128":
		if len(t) == 64 && reHex.MatchString(t) { return true, "" }
		return false, "SHAKE128 must be 64 hex chars (256-bit output)"
	case "shake256":
		if len(t) == 128 && reHex.MatchString(t) { return true, "" }
		return false, "SHAKE256 must be 128 hex chars (512-bit output)"
	case "ntlm", "lm":
		if len(t) == 32 && reHex.MatchString(t) { return true, "Note: 32-hex also used by MD5; ensure correct algo" }
		return false, strings.ToUpper(a)+" must be 32 hex chars"
	case "mysql":
		if reMySQL.MatchString(t) { return true, "" }
		return false, "MySQL 4.1+ must match *[A-F0-9]{40}"
	case "cisco", "cisco7":
		if reCisco7.MatchString(t) && len(t)%2 == 0 { return true, "" }
		return false, "Cisco7 must start with two digits followed by hex pairs"
	case "ldap_md5":
		if reLDAPmd5.MatchString(t) && isBase64(t[5:]) { return true, "" }
		return false, "LDAP MD5 must start with {MD5} and contain base64"
	case "ldap_sha1":
		if reLDAPsha1.MatchString(t) && isBase64(t[5:]) { return true, "" }
		return false, "LDAP SHA1 must start with {SHA} and contain base64"
	case "bcrypt":
		if reBcrypt.MatchString(t) && len(t) >= 60 { return true, "" }
		return false, "bcrypt must start with $2a$/$2b$/$2y$ and be ~60 chars"
	case "scrypt":
		if reScrypt.MatchString(t) { return true, "" }
		return false, "scrypt must be scrypt:<saltHex>:<keyHex>"
	case "argon2id":
		if reArgon2.MatchString(t) { return true, "" }
		return false, "argon2id must be argon2id:<saltHex>:<keyHex>"
	case "pbkdf2-sha1":
		if rePBKDF2.MatchString(t) && strings.HasPrefix(t, "pbkdf2-sha1:") { return true, "" }
		return false, "pbkdf2-sha1 must be pbkdf2-sha1:<saltHex>:<iter>:<keyHex>"
	case "pbkdf2-sha256":
		if rePBKDF2.MatchString(t) && strings.HasPrefix(t, "pbkdf2-sha256:") { return true, "" }
		return false, "pbkdf2-sha256 must be pbkdf2-sha256:<saltHex>:<iter>:<keyHex>"
	case "pbkdf2-sha512":
		if rePBKDF2.MatchString(t) && strings.HasPrefix(t, "pbkdf2-sha512:") { return true, "" }
		return false, "pbkdf2-sha512 must be pbkdf2-sha512:<saltHex>:<iter>:<keyHex>"
	default:
		return true, ""
	}
}

func isBase64(s string) bool { _, err := base64.StdEncoding.DecodeString(s); return err == nil }
