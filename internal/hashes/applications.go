package hashes

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

type applicationHasher struct { algo string }
func (h applicationHasher) Name() string { return h.algo }

func (h applicationHasher) getIterations(p Params) int {
	if p.PBKDF2Iterations > 0 {
		return p.PBKDF2Iterations
	}
	return 10000 // default
}

func (h applicationHasher) Hash(plain string, p Params) (string, error) {
	result, err := h.hashBytes([]byte(plain), p)
	if err != nil { return "", err }
	
	switch h.algo {
	case "ssha-256-base64", "ssha-512-base64":
		return base64.StdEncoding.EncodeToString(result), nil
	case "md5crypt", "sha256crypt", "sha512crypt":
		return h.cryptFormat(result, p), nil
	default:
		return hex.EncodeToString(result), nil
	}
}

func (h applicationHasher) Compare(target, plain string, p Params) (bool, error) {
	hash, err := h.Hash(plain, p)
	if err != nil { return false, err }
	return strings.EqualFold(hash, target), nil
}

func (h applicationHasher) hashBytes(plain []byte, p Params) ([]byte, error) {
	switch h.algo {
	case "mssql-2000":
		return h.mssql2000(plain, p.Salt), nil
	case "mssql-2005":
		return h.mssql2005(plain, p.Salt), nil
	case "mssql-2012":
		return h.mssql2012(plain, p.Salt), nil
	case "mongodb-scram-sha1":
		return h.mongoScramSha1(plain, p), nil
	case "mongodb-scram-sha256":
		return h.mongoScramSha256(plain, p), nil
	case "postgresql":
		return h.postgresql(plain, p.Salt), nil
	case "postgresql-cram-md5":
		return h.postgresqlCramMd5(plain, p.Salt), nil
	case "postgresql-scram-sha256":
		return h.postgresqlScramSha256(plain, p), nil
	case "oracle-h":
		return h.oracleH(plain, p.Salt), nil
	case "oracle-s":
		return h.oracleS(plain, p.Salt), nil
	case "oracle-t":
		return h.oracleT(plain, p.Salt), nil
	case "mysql-a-sha256crypt":
		return h.mysqlASha256crypt(plain, p), nil
	case "mysql-cram-sha1":
		return h.mysqlCramSha1(plain, p.Salt), nil
	case "mysql323":
		return h.mysql323(plain), nil
	case "mysql41":
		return h.mysql41(plain), nil
	case "sybase-ase":
		return h.sybaseAse(plain, p.Salt), nil
	case "dnssec-nsec3":
		return h.dnssecNsec3(plain, p.Salt), nil
	case "cisco-asa-md5":
		return h.ciscoAsaMd5(plain, p.Salt), nil
	case "cisco-ios-pbkdf2-sha256":
		return h.ciscoIosPbkdf2Sha256(plain, p), nil
	case "cisco-ios-scrypt":
		return h.ciscoIosScrypt(plain, p), nil
	case "cisco-ios-type4-sha256":
		return h.ciscoIosType4Sha256(plain, p.Salt), nil
	case "cisco-ise-sha256":
		return h.ciscoIseSha256(plain, p.Salt), nil
	case "cisco-pix-md5":
		return h.ciscoPixMd5(plain, p.Salt), nil
	case "citrix-netscaler-pbkdf2":
		return h.citrixNetscalerPbkdf2(plain, p), nil
	case "citrix-netscaler-sha1":
		return h.citrixNetscalerSha1(plain, p.Salt), nil
	case "citrix-netscaler-sha512":
		return h.citrixNetscalerSha512(plain, p.Salt), nil
	case "domain-cached-credentials":
		return h.domainCachedCredentials(plain, p.Salt), nil
	case "domain-cached-credentials2":
		return h.domainCachedCredentials2(plain, p), nil
	case "fortigate":
		return h.fortigate(plain, p.Salt), nil
	case "fortigate256":
		return h.fortigate256(plain, p.Salt), nil
	case "arubaos":
		return h.arubaos(plain, p.Salt), nil
	case "juniper-ive":
		return h.juniperIve(plain, p.Salt), nil
	case "juniper-netscreen":
		return h.juniperNetscreen(plain, p.Salt), nil
	case "juniper-sha1crypt":
		return h.juniperSha1crypt(plain, p), nil
	case "macos-10.4-10.6":
		return h.macos1046(plain, p.Salt), nil
	case "macos-10.7":
		return h.macos107(plain, p.Salt), nil
	case "macos-10.8-pbkdf2":
		return h.macos108Pbkdf2(plain, p), nil
	case "md5crypt":
		return h.md5crypt(plain, p), nil
	case "descrypt":
		return h.descrypt(plain, p.Salt), nil
	case "sha256crypt":
		return h.sha256crypt(plain, p), nil
	case "sha512crypt":
		return h.sha512crypt(plain, p), nil
	case "sm3crypt":
		return h.sm3crypt(plain, p), nil
	case "ssha-256-base64":
		hash := sha256.New()
		hash.Write(plain)
		hash.Write(p.Salt)
		result := hash.Sum(nil)
		return append(result, p.Salt...), nil
	case "ssha-512-base64":
		hash := sha512.New()
		hash.Write(plain)
		hash.Write(p.Salt)
		result := hash.Sum(nil)
		return append(result, p.Salt...), nil
	case "radmin3":
		return h.radmin3(plain, p.Salt), nil
	case "dahua-md5":
		return h.dahuaMd5(plain, p.Salt), nil
	case "redhat-389-ds-pbkdf2":
		return h.redhat389DsPbkdf2(plain, p), nil
	case "filezilla-server":
		return h.filezillaServer(plain, p.Salt), nil
	case "coldfusion-10":
		return h.coldfusion10(plain, p), nil
	case "apache-apr1-md5":
		return h.apacheApr1Md5(plain, p), nil
	case "episerver-6x-net4":
		return h.episerver6xNet4(plain, p.Salt), nil
	case "episerver-6x-net4-plus":
		return h.episerver6xNet4Plus(plain, p.Salt), nil
	case "hmailserver":
		return h.hmailserver(plain, p.Salt), nil
	case "nsldap-sha1":
		sha1Hash := sha1.Sum(plain)
		return sha1Hash[:], nil
	case "nsldaps-ssha1":
		hash := sha1.New()
		hash.Write(plain)
		hash.Write(p.Salt)
		result := hash.Sum(nil)
		return append(result, p.Salt...), nil
	case "sap-codvn-b":
		return h.sapCodvnB(plain), nil
	case "sap-codvn-f":
		return h.sapCodvnF(plain), nil
	case "sap-codvn-h-issha1":
		return h.sapCodvnHIssha1(plain, p.Salt), nil
	case "sap-codvn-h-issha512":
		return h.sapCodvnHIssha512(plain, p.Salt), nil
	case "rsa-netwitness-sha256":
		return h.rsaNetwitnessSha256(plain, p.Salt), nil
	case "adobe-aem-sha256":
		return h.adobeAemSha256(plain, p.Salt), nil
	case "adobe-aem-sha512":
		return h.adobeAemSha512(plain, p.Salt), nil
	case "peoplesoft":
		return h.peoplesoft(plain), nil
	case "peoplesoft-ps-token":
		return h.peoplesoftPsToken(plain, p.Salt), nil
	case "netiq-sspr-md5":
		return h.netiqSsprMd5(plain, p.Salt), nil
	case "netiq-sspr-pbkdf2-sha1":
		return h.netiqSsprPbkdf2Sha1(plain, p), nil
	case "netiq-sspr-pbkdf2-sha256":
		return h.netiqSsprPbkdf2Sha256(plain, p), nil
	case "netiq-sspr-pbkdf2-sha512":
		return h.netiqSsprPbkdf2Sha512(plain, p), nil
	case "netiq-sspr-sha1-salt":
		return h.netiqSsprSha1Salt(plain, p.Salt), nil
	case "netiq-sspr-sha256-salt":
		return h.netiqSsprSha256Salt(plain, p.Salt), nil
	case "netiq-sspr-sha512-salt":
		return h.netiqSsprSha512Salt(plain, p.Salt), nil
	case "netiq-sspr-sha1":
		sha1Hash := sha1.Sum(plain)
		return sha1Hash[:], nil
	case "solarwinds-orion":
		return h.solarwindsOrion(plain, p.Salt), nil
	case "solarwinds-orion-v2":
		return h.solarwindsOrionV2(plain, p.Salt), nil
	case "solarwinds-serv-u":
		return h.solarwindsServU(plain, p.Salt), nil
	case "lotus-notes-5":
		return h.lotusNotes5(plain, p.Salt), nil
	case "lotus-notes-6":
		return h.lotusNotes6(plain, p.Salt), nil
	case "lotus-notes-8":
		return h.lotusNotes8(plain, p.Salt), nil
	case "openedge-progress":
		return h.openedgeProgress(plain, p.Salt), nil
	case "oracle-tm-sha256":
		return h.oracleTmSha256(plain, p.Salt), nil
	case "huawei-sha1-md5-salt":
		md5Hash := md5.Sum(plain)
		combined := append(md5Hash[:], p.Salt...)
		sha1Hash := sha1.Sum(combined)
		return sha1Hash[:], nil
	case "authme-sha256":
		return h.authmeSha256(plain, p.Salt), nil
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", h.algo)
	}
}

func (h applicationHasher) mssql2000(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha1.Sum(combined)
	return hash[:]
}

func (h applicationHasher) mssql2005(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha1.Sum(combined)
	return hash[:]
}

func (h applicationHasher) mssql2012(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha512.Sum512(combined)
	return hash[:]
}

func (h applicationHasher) mongoScramSha1(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 20, sha1.New)
}

func (h applicationHasher) mongoScramSha256(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 32, sha256.New)
}

func (h applicationHasher) postgresql(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:]
}

func (h applicationHasher) postgresqlCramMd5(plain, salt []byte) []byte {
	hash := md5.New()
	hash.Write(salt)
	hash.Write(plain)
	return hash.Sum(nil)
}

func (h applicationHasher) postgresqlScramSha256(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 32, sha256.New)
}

func (h applicationHasher) oracleH(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:]
}

func (h applicationHasher) oracleS(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha1.Sum(combined)
	return hash[:]
}

func (h applicationHasher) oracleT(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha512.Sum512(combined)
	return hash[:]
}

func (h applicationHasher) mysqlASha256crypt(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 32, sha256.New)
}

func (h applicationHasher) mysqlCramSha1(plain, salt []byte) []byte {
	hash := sha1.New()
	hash.Write(salt)
	hash.Write(plain)
	return hash.Sum(nil)
}

func (h applicationHasher) mysql323(plain []byte) []byte {
	hash := md5.Sum(plain)
	return hash[:]
}

func (h applicationHasher) mysql41(plain []byte) []byte {
	first := sha1.Sum(plain)
	second := sha1.Sum(first[:])
	return second[:]
}

func (h applicationHasher) sybaseAse(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (h applicationHasher) dnssecNsec3(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha1.Sum(combined)
	return hash[:]
}

func (h applicationHasher) ciscoAsaMd5(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:]
}

func (h applicationHasher) ciscoIosPbkdf2Sha256(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 32, sha256.New)
}

func (h applicationHasher) ciscoIosScrypt(plain []byte, p Params) []byte {
	result, _ := scrypt.Key(plain, p.Salt, p.ScryptN, p.ScryptR, p.ScryptP, 32)
	return result
}

func (h applicationHasher) ciscoIosType4Sha256(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (h applicationHasher) ciscoIseSha256(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (h applicationHasher) ciscoPixMd5(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:]
}

func (h applicationHasher) citrixNetscalerPbkdf2(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 32, sha256.New)
}

func (h applicationHasher) citrixNetscalerSha1(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha1.Sum(combined)
	return hash[:]
}

func (h applicationHasher) citrixNetscalerSha512(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha512.Sum512(combined)
	return hash[:]
}

func (h applicationHasher) domainCachedCredentials(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:]
}

func (h applicationHasher) domainCachedCredentials2(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 32, sha256.New)
}

func (h applicationHasher) fortigate(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha1.Sum(combined)
	return hash[:]
}

func (h applicationHasher) fortigate256(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (h applicationHasher) arubaos(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:]
}

func (h applicationHasher) juniperIve(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:]
}

func (h applicationHasher) juniperNetscreen(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:]
}

func (h applicationHasher) juniperSha1crypt(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 20, sha1.New)
}

func (h applicationHasher) macos1046(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha1.Sum(combined)
	return hash[:]
}

func (h applicationHasher) macos107(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha512.Sum512(combined)
	return hash[:]
}

func (h applicationHasher) macos108Pbkdf2(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 64, sha512.New)
}

func (h applicationHasher) md5crypt(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, 1000, 16, md5.New)
}

func (h applicationHasher) descrypt(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:8]
}

func (h applicationHasher) sha256crypt(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, 5000, 32, sha256.New)
}

func (h applicationHasher) sha512crypt(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, 5000, 64, sha512.New)
}

func (h applicationHasher) sm3crypt(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, 5000, 32, sha256.New)
}

func (h applicationHasher) cryptFormat(result []byte, p Params) string {
	return "$6$" + string(p.Salt) + "$" + base64.StdEncoding.EncodeToString(result)
}

func (h applicationHasher) radmin3(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:]
}

func (h applicationHasher) dahuaMd5(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:]
}

func (h applicationHasher) redhat389DsPbkdf2(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 32, sha256.New)
}

func (h applicationHasher) filezillaServer(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha512.Sum512(combined)
	return hash[:]
}

func (h applicationHasher) coldfusion10(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 32, sha256.New)
}

func (h applicationHasher) apacheApr1Md5(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, 1000, 16, md5.New)
}

func (h applicationHasher) episerver6xNet4(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (h applicationHasher) episerver6xNet4Plus(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha512.Sum512(combined)
	return hash[:]
}

func (h applicationHasher) hmailserver(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (h applicationHasher) sapCodvnB(plain []byte) []byte {
	hash := md5.Sum(plain)
	return hash[:]
}

func (h applicationHasher) sapCodvnF(plain []byte) []byte {
	hash := sha1.Sum(plain)
	return hash[:]
}

func (h applicationHasher) sapCodvnHIssha1(plain, salt []byte) []byte {
	hash := sha1.New()
	hash.Write(plain)
	hash.Write(salt)
	result := hash.Sum(nil)
	return append(result, salt...)
}

func (h applicationHasher) sapCodvnHIssha512(plain, salt []byte) []byte {
	hash := sha512.New()
	hash.Write(plain)
	hash.Write(salt)
	result := hash.Sum(nil)
	return append(result, salt...)
}

func (h applicationHasher) rsaNetwitnessSha256(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (h applicationHasher) adobeAemSha256(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (h applicationHasher) adobeAemSha512(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha512.Sum512(combined)
	return hash[:]
}

func (h applicationHasher) peoplesoft(plain []byte) []byte {
	hash := sha1.Sum(plain)
	return hash[:]
}

func (h applicationHasher) peoplesoftPsToken(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (h applicationHasher) netiqSsprMd5(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:]
}

func (h applicationHasher) netiqSsprPbkdf2Sha1(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 20, sha1.New)
}

func (h applicationHasher) netiqSsprPbkdf2Sha256(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 32, sha256.New)
}

func (h applicationHasher) netiqSsprPbkdf2Sha512(plain []byte, p Params) []byte {
	return pbkdf2.Key(plain, p.Salt, h.getIterations(p), 64, sha512.New)
}

func (h applicationHasher) netiqSsprSha1Salt(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha1.Sum(combined)
	return hash[:]
}

func (h applicationHasher) netiqSsprSha256Salt(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (h applicationHasher) netiqSsprSha512Salt(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha512.Sum512(combined)
	return hash[:]
}

func (h applicationHasher) solarwindsOrion(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha1.Sum(combined)
	return hash[:]
}

func (h applicationHasher) solarwindsOrionV2(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (h applicationHasher) solarwindsServU(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha512.Sum512(combined)
	return hash[:]
}

func (h applicationHasher) lotusNotes5(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:]
}

func (h applicationHasher) lotusNotes6(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha1.Sum(combined)
	return hash[:]
}

func (h applicationHasher) lotusNotes8(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (h applicationHasher) openedgeProgress(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := md5.Sum(combined)
	return hash[:]
}

func (h applicationHasher) oracleTmSha256(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (h applicationHasher) authmeSha256(plain, salt []byte) []byte {
	combined := append(plain, salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func init() {
	algos := []string{
		"mssql-2000", "mssql-2005", "mssql-2012", "mongodb-scram-sha1", "mongodb-scram-sha256",
		"postgresql", "postgresql-cram-md5", "postgresql-scram-sha256", "oracle-h", "oracle-s", "oracle-t",
		"mysql-a-sha256crypt", "mysql-cram-sha1", "mysql323", "mysql41", "sybase-ase", "dnssec-nsec3",
		"cisco-asa-md5", "cisco-ios-pbkdf2-sha256", "cisco-ios-scrypt", "cisco-ios-type4-sha256",
		"cisco-ise-sha256", "cisco-pix-md5", "citrix-netscaler-pbkdf2", "citrix-netscaler-sha1",
		"citrix-netscaler-sha512", "domain-cached-credentials", "domain-cached-credentials2",
		"fortigate", "fortigate256", "arubaos", "juniper-ive", "juniper-netscreen", "juniper-sha1crypt",
		"macos-10.4-10.6", "macos-10.7", "macos-10.8-pbkdf2", "md5crypt", "descrypt", "sha256crypt",
		"sha512crypt", "sm3crypt", "ssha-256-base64", "ssha-512-base64", "radmin3", "dahua-md5",
		"redhat-389-ds-pbkdf2", "filezilla-server", "coldfusion-10", "apache-apr1-md5",
		"episerver-6x-net4", "episerver-6x-net4-plus", "hmailserver", "nsldap-sha1", "nsldaps-ssha1",
		"sap-codvn-b", "sap-codvn-f", "sap-codvn-h-issha1", "sap-codvn-h-issha512",
		"rsa-netwitness-sha256", "adobe-aem-sha256", "adobe-aem-sha512", "peoplesoft", "peoplesoft-ps-token",
		"netiq-sspr-md5", "netiq-sspr-pbkdf2-sha1", "netiq-sspr-pbkdf2-sha256", "netiq-sspr-pbkdf2-sha512",
		"netiq-sspr-sha1-salt", "netiq-sspr-sha256-salt", "netiq-sspr-sha512-salt", "netiq-sspr-sha1",
		"solarwinds-orion", "solarwinds-orion-v2", "solarwinds-serv-u", "lotus-notes-5", "lotus-notes-6",
		"lotus-notes-8", "openedge-progress", "oracle-tm-sha256", "huawei-sha1-md5-salt", "authme-sha256",
	}
	
	for _, algo := range algos {
		Register(applicationHasher{algo})
	}
}
