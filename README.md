[![goreleaser](https://github.com/5amu/dnshunter/actions/workflows/goreleaser.yml/badge.svg)](https://github.com/5amu/dnshunter/actions/workflows/goreleaser.yml)

# ~# dnshunter

Make DNS and BGP assessment easier. Just a program to perform many DNS checks automatically. 

## Install

Install using go:

```
go install -v github.com/5amu/dnshunter/cmd/dnshunter@latest
```

Or visit the release page and get the latest for your arch.

## Todo

* [ ] Implement BGP IRR check
* [ ] Find a way to query the ROA for ASNs (bgpmon is now owned by Cisco)
* [ ] Implement Subdomain takeover check if possible
