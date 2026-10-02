<h1 align="center">
    <br>
    <img src="assets/dnshunter_logo.png" width="200px" alt="DNSHunter">
    <br>
    DNS Hunter
</h1>

<h4 align="center">Assess the DNS, e-mail and BGP security of a domain.</h4>

<p align="center">
    <img src="https://img.shields.io/github/go-mod/go-version/5amu/dnshunter">
    <img src="https://github.com/5amu/dnshunter/actions/workflows/goreleaser.yml/badge.svg">
    <img src="https://github.com/5amu/dnshunter/actions/workflows/lint-test.yml/badge.svg">
    <img src="https://github.com/5amu/dnshunter/actions/workflows/build-test.yml/badge.svg">
</p>

---

DNSHunter is a tool for security professionals. Given a domain, it checks:

- **the DNS zone and its authoritative nameservers**: delegation, glue, zone transfers, amplification, open recursion, version disclosure, DNSSEC, SOA and CAA;
- **its e-mail authentication records**: SPF, DMARC and DKIM;
- **the routing infrastructure behind it**: the autonomous systems (ASNs) announcing its nameservers and the addresses the domain points to, their RPKI (ROA) and IRR registration, and AS and geographic redundancy.

Addresses hosted by **cloud, CDN or hosting providers** (Cloudflare, AWS, Google, Azure, Akamai, OVH, Hetzner, Aruba, …) are recognized and skipped by the BGP analysis. Their AS is shared infrastructure that the domain owner does not control. Every other AS is profiled in depth.

Every finding has a status (`pass`, `fail`, `info`, `skipped`, `error`). Failures also carry a severity (`low`, `medium`, `high`, `critical`) and, where possible, a command to reproduce them (PoC).

## Install

```
go install -v github.com/5amu/dnshunter/cmd/dnshunter@latest
```

Or download a binary from the [release page](https://github.com/5amu/dnshunter/releases).

## Usage

```bash
dnshunter example.com                       # run every check
dnshunter -d example.com -c dns,mail        # run only the DNS and e-mail checks
dnshunter -d example.com -c asn,roa,irr     # analyze the routing of the domain
dnshunter -d example.com -x zone,any        # everything but AXFR and ANY
dnshunter -d example.com -o report.json -md report.md
dnshunter -d example.com -json | jq '.summary'
dnshunter -d example.com -s -fail-on high   # one line per check, exit code 2 on high findings (CI)
dnshunter -l                                # list the available checks
dnshunter -h                                # all the flags
```

The domain can be any name: a registrable domain (`example.co.uk`), a subdomain (`www.example.com`, analyzed within its zone), a URL or an IDN.

### Checks

| ID (aliases) | Group | What is verified |
|---|---|---|
| `ns` (`delegation`, `lame`) | dns | At least 2 nameservers, same NS set at the parent and in the zone, no lame servers (AA flag), nameserver names that resolve, **nameserver domains that are not registered (zone takeover)**, /24 diversity, IPv6 reachability |
| `soa` | dns | SOA timers (RIPE-203, RFC 1912, RFC 2308), serial format and consistency across nameservers |
| `glue` | dns | Glue records at the parent for in-bailiwick nameservers: missing, stale or incomplete glue |
| `zone` (`axfr`) | dns | Unauthenticated zone transfers (the transferred records are included in the report) |
| `any` | dns | Full answers to ANY queries over UDP and their amplification factor (RFC 8482) |
| `recursion` (`openresolver`) | dns | Authoritative nameservers acting as open resolvers |
| `version` (`chaos`) | dns | Software version and identity disclosure (`version.bind`, `hostname.bind`, `id.server`) |
| `dnssec` | dns | DS at the parent, DNSKEY on every nameserver, DS ↔ KSK match, signature validity and expiry, deprecated algorithms and digests (RFC 8624), short RSA keys, NSEC zone walking, NSEC3 parameters (RFC 9276) |
| `caa` | dns | CAA records restricting certificate issuance (RFC 8659), inherited ones included |
| `spf` | mail | Missing/multiple records, `all` qualifier, `redirect=`, recursive `include:` tree, 10 DNS lookups and void lookup limits, includes ending in `+all`, dangling includes, `ptr`, overly broad `ip4`/`ip6` ranges |
| `dmarc` | mail | Missing/multiple records, policy (`none`/`quarantine`/`reject`), subdomain policy, `pct`, reporting addresses and their external authorization, organizational domain fallback |
| `dkim` | mail | Keys published under 50+ common selectors (plus `-dkim-selectors`), key size (RFC 8301), testing mode, SHA-1, revoked keys |
| `asn` | bgp | **ASN of every address the domain points to.** Provider networks are reported and skipped. Other ASes are profiled: holder, registration, likely ownership, registered network, upstream providers (single-homing), BGP visibility, multiple origins (MOAS / possible hijack), IRR and RPKI coverage of the AS prefixes, abuse contact, non-public addresses |
| `geo` (`georedundancy`) | bgp | Nameservers spread over different ASes and countries (RFC 2182), with anycast providers taken into account |
| `roa` (`rpki`) | bgp | RPKI origin validation of the prefixes carrying the nameservers and the domain addresses: invalid, not-found, loose max-length ROAs (RFC 9319) |
| `irr` | bgp | IRR route objects for those prefixes: missing, registered only for other origins, covered only by less-specific objects |

Groups: `all` (default), `dns`, `mail`, `bgp`.

### ASN analysis and providers

For each address of the domain (A/AAAA records, falling back to `www.` when the apex has none), DNSHunter:

1. flags private, reserved and unrouted addresses;
2. maps the address to its origin AS and announced prefix (Team Cymru, with RIPEstat as fallback);
3. checks whether the AS belongs to a provider, using a built-in database of well-known provider ASNs and, as a fallback, keywords in the AS name (`HOSTING`, `CLOUD`, `CDN`, vendor names);
4. for non-provider ASes, profiles the AS through RIPEstat and Team Cymru data.

Flags controlling this behaviour:

- `-include-providers` analyzes provider networks too;
- `-provider-asns 64500,64501` treats additional ASNs as providers;
- `-max-prefixes N` sets how many announced prefixes per AS are sampled for the RPKI coverage (default 20).

### Output

The console output streams the results as checks complete and ends with a summary of all the issues, most severe first. `-v` adds descriptions, references, every detail and the PoC of every finding; `-s` prints one line per check.

`-o file.json` (or `-json` for stdout) writes a machine-readable report and `-md file.md` a Markdown report ready to paste into an assessment.

Exit codes: `0` success, `1` error, `2` a finding at or above the `-fail-on` severity was found.

### Network requirements and data sources

| Purpose | Destination |
|---|---|
| Recursive lookups | the resolvers given with `-r` (default `8.8.8.8,1.1.1.1`), UDP/TCP 53 |
| Nameserver checks | the authoritative nameservers and the parent zone servers, UDP/TCP 53 (`-6` to also use IPv6) |
| IP to ASN mapping | [Team Cymru](https://www.team-cymru.com/ip-asn-mapping) over DNS (`asn.cymru.com`) |
| RPKI, IRR, visibility, neighbours, geolocation | [RIPEstat Data API](https://stat.ripe.net/docs/data-api/), HTTPS (`-no-ripestat` to disable) |
| IRR fallback | [RADb](https://www.radb.net/) whois, TCP 43 (`-no-irrd` to disable) |

Some networks transparently redirect DNS traffic to their own resolver. DNSHunter detects this at startup and warns you, because per-nameserver results would then describe the interceptor rather than the real servers.

## Development

```bash
go test -race ./...
golangci-lint run
```

The tests run every check end to end against in-process DNS servers and a fake RIPEstat API (see `internal/dnstest` and `internal/testenv`), so they need no network access.
