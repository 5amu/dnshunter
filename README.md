<h1 align="center">
    <br>
    <img src="assets/dnshunter_logo.png" width="200px" alt="DNSHunter">
    <br>
    DNS Hunter
</h1>

<h4 align="center">A program to perform many DNS checks automatically.</h4>

<p align="center">
    <img src="https://img.shields.io/github/go-mod/go-version/5amu/dnshunter">
    <img src="https://github.com/5amu/dnshunter/actions/workflows/goreleaser.yml/badge.svg">
    <img src="https://github.com/5amu/dnshunter/actions/workflows/lint-test.yml/badge.svg">
    <img src="https://github.com/5amu/dnshunter/actions/workflows/release.yml/badge.svg">
</p>

---

DNSHunter is a tool to perform various checks on a DNS zone. It is aimed to security professionals that will check the security of a Nameserver and BGP infrastructure.

## Install

Install using go:

```
go install -v github.com/5amu/dnshunter/cmd/dnshunter@latest
```

Or visit the release page and get the latest for your arch.

## Usage

It's still in heavy development and arguments might change in the future, so refer to the help switch:

```bash
dnshunter -h
```
