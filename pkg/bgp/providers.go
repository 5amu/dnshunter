package bgp

import (
	"fmt"
	"strings"
	"unicode"
)

// Provider kinds.
const (
	KindCloud    = "cloud"
	KindCDN      = "cdn"
	KindHosting  = "hosting"
	KindDNS      = "dns"
	KindSecurity = "security"
)

// Provider describes a cloud, CDN, hosting or managed DNS operator. Addresses
// in a provider's network are shared infrastructure: analyzing the provider's
// AS tells nothing about the security posture of the domain owner.
type Provider struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Anycast is true when the provider serves DNS over anycast, which
	// mitigates geographic concentration of nameservers.
	Anycast bool `json:"anycast,omitempty"`
	// Reason explains how the provider was identified.
	Reason string `json:"reason"`
}

type providerInfo struct {
	name    string
	kind    string
	anycast bool
}

// knownProviders maps well-known ASNs to their operator.
var knownProviders = map[uint32]providerInfo{}

func register(name, kind string, anycast bool, asns ...uint32) {
	for _, a := range asns {
		knownProviders[a] = providerInfo{name: name, kind: kind, anycast: anycast}
	}
}

func init() {
	register("Cloudflare", KindCDN, true, 13335, 209242)
	register("Amazon Web Services", KindCloud, true, 16509, 14618, 8987, 7224, 38895)
	register("Google", KindCloud, true, 15169, 396982, 19527, 36040, 43515, 139070, 36492)
	register("Microsoft", KindCloud, true, 8075, 8068, 8069, 12076, 3598)
	register("Akamai", KindCDN, true, 20940, 16625, 16702, 21342, 21357, 32787, 33905, 34164, 35994, 36183, 12222, 18680, 24319, 43639)
	register("Akamai Connected Cloud (Linode)", KindCloud, false, 63949)
	register("Fastly", KindCDN, true, 54113)
	register("Imperva Incapsula", KindSecurity, true, 19551)
	register("Sucuri", KindSecurity, true, 30148)
	register("StackPath", KindCDN, true, 12989, 33438, 20446)
	register("Edgio (Edgecast)", KindCDN, true, 15133)
	register("Edgio (Limelight)", KindCDN, true, 22822)
	register("CDN77", KindCDN, true, 60068)
	register("BunnyCDN", KindCDN, true, 200325)
	register("Gcore", KindCDN, true, 199524)
	register("OVHcloud", KindHosting, false, 16276, 35540)
	register("Hetzner", KindHosting, false, 24940, 213230, 212317)
	register("DigitalOcean", KindCloud, false, 14061)
	register("Vultr", KindCloud, false, 20473)
	register("Oracle Cloud", KindCloud, false, 31898)
	register("Oracle Dyn", KindDNS, true, 33517)
	register("Alibaba Cloud", KindCloud, false, 45102, 37963)
	register("Tencent Cloud", KindCloud, false, 132203, 45090)
	register("Huawei Cloud", KindCloud, false, 136907, 55990)
	register("IBM Cloud", KindCloud, false, 36351)
	register("Rackspace", KindHosting, false, 19994, 27357, 33070)
	register("Leaseweb", KindHosting, false, 60781, 16265, 28753)
	register("Scaleway", KindCloud, false, 12876)
	register("Contabo", KindHosting, false, 51167)
	register("IONOS", KindHosting, false, 8560)
	register("Aruba S.p.A.", KindHosting, false, 31034)
	register("Register.it", KindHosting, false, 39729)
	register("Hostinger", KindHosting, false, 47583)
	register("Newfold Digital (Bluehost/HostGator)", KindHosting, false, 46606)
	register("GoDaddy", KindHosting, false, 26496, 398101)
	register("Namecheap", KindHosting, false, 22612)
	register("Squarespace", KindHosting, false, 53831)
	register("Wix", KindHosting, false, 58182)
	register("Automattic (WordPress.com)", KindHosting, false, 2635)
	register("GitHub", KindHosting, false, 36459)
	register("Fly.io", KindCloud, true, 40509)
	register("Zscaler", KindSecurity, false, 22616, 53813)
	register("Yandex Cloud", KindCloud, false, 200350)
	register("Selectel", KindHosting, false, 49505)
	register("Hostwinds", KindHosting, false, 54290)
	register("Liquid Web", KindHosting, false, 32244)
	register("DreamHost", KindHosting, false, 26347)
	register("Strato", KindHosting, false, 6724)
	register("netcup", KindHosting, false, 197540)
	register("Infomaniak", KindHosting, false, 29222)
	register("Seeweb", KindHosting, false, 12637)
	register("Psychz Networks", KindHosting, false, 40676)
	register("QuadraNet", KindHosting, false, 8100)
	register("ColoCrossing", KindHosting, false, 36352)
	register("M247", KindHosting, false, 9009)
	register("FranTech (BuyVM)", KindHosting, false, 53667)
	register("NS1", KindDNS, true, 62597)
	register("Vercara UltraDNS", KindDNS, true, 12008)
}

// vendorKeywords identify providers from their AS name (substring match).
var vendorKeywords = []struct{ keyword, name, kind string }{
	{"CLOUDFLARE", "Cloudflare", KindCDN},
	{"AMAZON", "Amazon Web Services", KindCloud},
	{"AKAMAI", "Akamai", KindCDN},
	{"FASTLY", "Fastly", KindCDN},
	{"INCAPSULA", "Imperva Incapsula", KindSecurity},
	{"IMPERVA", "Imperva", KindSecurity},
	{"SUCURI", "Sucuri", KindSecurity},
	{"DIGITALOCEAN", "DigitalOcean", KindCloud},
	{"HETZNER", "Hetzner", KindHosting},
	{"LINODE", "Linode", KindCloud},
	{"VULTR", "Vultr", KindCloud},
	{"CHOOPA", "Vultr (Choopa)", KindCloud},
	{"ALIBABA", "Alibaba Cloud", KindCloud},
	{"TENCENT", "Tencent Cloud", KindCloud},
	{"LEASEWEB", "Leaseweb", KindHosting},
	{"SCALEWAY", "Scaleway", KindCloud},
	{"CONTABO", "Contabo", KindHosting},
	{"HOSTINGER", "Hostinger", KindHosting},
	{"GODADDY", "GoDaddy", KindHosting},
	{"NAMECHEAP", "Namecheap", KindHosting},
	{"SQUARESPACE", "Squarespace", KindHosting},
	{"AUTOMATTIC", "Automattic", KindHosting},
	{"STACKPATH", "StackPath", KindCDN},
	{"EDGECAST", "Edgio (Edgecast)", KindCDN},
	{"LIMELIGHT", "Edgio (Limelight)", KindCDN},
	{"ZSCALER", "Zscaler", KindSecurity},
	{"RACKSPACE", "Rackspace", KindHosting},
	{"SOFTLAYER", "IBM Cloud (SoftLayer)", KindCloud},
	{"GOOGLE", "Google", KindCloud},
	{"MICROSOFT", "Microsoft", KindCloud},
	{"AZURE", "Microsoft Azure", KindCloud},
}

// tokenKeywords identify providers from whole words of their AS name.
var tokenKeywords = map[string]providerInfo{
	"OVH":         {name: "OVHcloud", kind: KindHosting},
	"AWS":         {name: "Amazon Web Services", kind: KindCloud},
	"GCP":         {name: "Google Cloud", kind: KindCloud},
	"IONOS":       {name: "IONOS", kind: KindHosting},
	"CDN77":       {name: "CDN77", kind: KindCDN},
	"ORACLE":      {name: "Oracle", kind: KindCloud},
	"HOSTING":     {kind: KindHosting},
	"WEBHOSTING":  {kind: KindHosting},
	"HOSTER":      {kind: KindHosting},
	"CDN":         {kind: KindCDN},
	"CLOUD":       {kind: KindCloud},
	"DATACENTER":  {kind: KindHosting},
	"DATACENTRE":  {kind: KindHosting},
	"COLOCATION":  {kind: KindHosting},
	"VPS":         {kind: KindHosting},
	"WEBSERVICES": {kind: KindCloud},
}

// ProviderDB classifies autonomous systems as providers.
type ProviderDB struct {
	extra map[uint32]string
	// DisableHeuristics turns off AS name keyword matching.
	DisableHeuristics bool
}

// NewProviderDB returns the built-in provider database.
func NewProviderDB() *ProviderDB { return &ProviderDB{extra: map[uint32]string{}} }

// Add registers an additional provider ASN.
func (db *ProviderDB) Add(asn uint32, name string) {
	if name == "" {
		name = fmt.Sprintf("user-defined provider AS%d", asn)
	}
	db.extra[asn] = name
}

// Classify returns the provider operating asn (whose registered name is
// asName), or nil when the AS does not look like a provider.
func (db *ProviderDB) Classify(asn uint32, asName string) *Provider {
	if name, ok := db.extra[asn]; ok {
		return &Provider{Name: name, Kind: KindHosting, Reason: fmt.Sprintf("AS%d marked as provider by the user", asn)}
	}
	if p, ok := knownProviders[asn]; ok {
		return &Provider{Name: p.name, Kind: p.kind, Anycast: p.anycast, Reason: fmt.Sprintf("AS%d is a known %s provider network", asn, p.kind)}
	}
	if db.DisableHeuristics || asName == "" {
		return nil
	}
	upper := strings.ToUpper(asName)
	for _, k := range vendorKeywords {
		if strings.Contains(upper, k.keyword) {
			return &Provider{Name: k.name, Kind: k.kind, Reason: fmt.Sprintf("AS name %q contains %q", asName, k.keyword)}
		}
	}
	tokens := strings.FieldsFunc(upper, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	for _, tok := range tokens {
		if p, ok := tokenKeywords[tok]; ok {
			name := p.name
			if name == "" {
				name = asName
			}
			return &Provider{Name: name, Kind: p.kind, Reason: fmt.Sprintf("AS name %q contains the word %q", asName, tok)}
		}
	}
	return nil
}
