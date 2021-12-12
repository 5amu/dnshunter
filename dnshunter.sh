#!/bin/sh
#
# Author: 5amu
#

### IO from https://blackarch.org/strap.sh
###############################################################################

BOLD="$(tput bold)"; RESET="$(tput sgr0)"
RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"

# simple error message wrapper
err() { echo >&2 "${BOLD}${RED}[-] ERROR: ${*}${RESET}"; exit 1337; }

# simple warning message wrapper
warn() { echo >&2 "${BOLD}${YELLOW}[!] WARNING: ${*}${RESET}"; }

# simple message wrapper
msg()  { echo "${BOLD}${GREEN}[+] ${*}${RESET}"; }

# simple echo info wrapper
info() { echo "${*}"; }

### DNS version and banner
###############################################################################

version()
{
    msg "[version] Checking info of nameservers"
    # get all nameservers for a specific domain and launch nmap on them
    for ns in $NAMESERVERS; do
        nmap --script dns-nsid -p 53 -Pn -sV -oG - "$ns"
        dig version.bind CHAOS TXT @"$ns" +short
    done
}

### SOA information and suggestions
### https://en.wikipedia.org/wiki/SOA_record
###############################################################################

soa_info_msg()
{
    [ ${1} -eq 0 ] && return

    info "It is reccomended to set this records properly, following the"
    info "RIPE-203 guides (https://www.ripe.net/publications/docs/ripe-203),"
    info "to improve performance due to less computational steps to comform"
    info "to global standards. This might be unapplicable depending on the"
    info "purpose. TLDR: if you know what you're doing, this is fine."
}

soa_info()
{
    # Variable to be set if verbose message is needed
    ret_code=0

    msg "[soa_info] Running SOA checks"
    soa=$( dig SOA $1 +short +nostats ) 

    name=$(    echo "$soa" | awk '{print $1}' )
    soa_r=$(   echo "$soa" | awk '{print $2}' )
    serial=$(  echo "$soa" | awk '{print $3}' )
    refresh=$( echo "$soa" | awk '{print $4}' )
    retry=$(   echo "$soa" | awk '{print $5}' )
    expire=$(  echo "$soa" | awk '{print $6}' )
    ttl=$(     echo "$soa" | awk '{print $7}' )

    # check if the soa values are compliant with RIPE-203
    # https://www.ripe.net/publications/docs/ripe-203
    #####################################################

    info "Zone name: $name"
    info "Start of Authority: $soa_r"

    # if serial is not in the acceptable range, then does not follow RIPE-203
    # dummy_u serial created today, with id=99, dummy_l is created at time 0 
    # (1 gen 1970) with id=00, this value should tell the day and revision in
    # which it was last modified
    dummy_u="$( date +'%Y%m%d' )99"; dummy_l="$( date -d @0 +'%Y%m%d' )00"
    if date +'%Y%m%d' -d "${serial%??}" >/dev/null 2>&1 \
    || [ $dummy_u -lt $serial ] || [ $dummy_l -gt $serial ]; then
        warn "Serial number: $serial - should follow standard (RIPE-203)"
        ret_code=1
    else
        info "Serial number: $serial"
    fi

    # refresh and retry time(s) should be fairly high if the zone is stable
    if [ $(date -d @86400 +'%d%H%M%S') -gt $(date -d @$refresh +'%d%H%M%S') ]; then
        warn "Refresh: $refresh - should be higher (RIPE-203)"
        ret_code=1
    else
        info "Refresh: $refresh"
    fi
    if [ $(date -d @7200 +'%d%H%M%S') -gt $(date -d @$retry +'%d%H%M%S') ]; then
        warn "Retry: $retry - should be higher (RIPE-203)"
        ret_code=1
    else
        info "Retry: $retry"
    fi


    # a value of a week or two has proven to be way too short, so a longer 
    # time must be used 
    if [ $(date -d @3600000 +'%d%H%M%S') -gt $(date -d @$expire +'%d%H%M%S') ]; then
        warn "Expire: $expire - should be higher (RIPE-203)"
        ret_code=1
    else
        info "Expire: $expire"
    fi
    
    # this could be correct either way depending on the paradigm, so no checks
    # will be performed on this value
    info "TTL: $ttl"
    
    return $ret_code
}

### DNS glue records for nameservers
### https://www.barryodonovan.com/2011/02/16/querying-for-dns-glue-records
###############################################################################

glue_record_msg()
{
    [ ${1} -eq 0 ] && return
    info "Glue records are meant to avoid cyclic queries between nameservers"
    info "You should 'Glue' records for NS in the additional section of the"
    info "answer. The severity of this misconfiguration is arguably medium"
}

glue_record()
{
    msg "[glue_records] Looking for configured glue record for nameservers"
    ret_code=0
    for ns in $NAMESERVERS; do
        if ! dig NS $1 +noall +additional @"$ns" | grep "${ns}.*A" &>/dev/null; then
            warn "GLUE record not set for nameserver $ns in ADDITIONAL section"
            ret_code=1
        fi
    done; return $ret_code
}

### ANY queries
### https://www.cisa.gov/uscert/ncas/alerts/TA13-088A
###############################################################################

any_query_msg()
{
    [ ${1} -eq 0 ] && return
}

any_query()
{
    msg "[any_query] Checking if the DNS answers to ANY queries"
    ret_code=0
    for ns in $NAMESERVERS; do
        if [ "$( dig ANY $1 @"$ns" +noall +answer | wc -l )" -gt 0 ]; then
            warn "DNS $ns answers to ANY queries"
            ret_code=1
        fi
    done; return $ret_code
}

### DNS zone transfer checker
### https://www.iana.org/go/rfc1035
### https://www.rfc-editor.org/rfc/rfc5936.html
###############################################################################

zone_transfer_msg()
{
    [ ${1} -eq 0 ] && return
    info "The nameserver allows zone transfers from unauthorized sources, this"
    info "leads to the disclosure of all the zone's domains handled by the dns" 
    info "(at best). In the worse case scenario, the attacker might be able to" 
    info "get ownership on the zone handled by the dns."
}

zone_transfer()
{
    ret_code=0
    msg "[zone_transfer] Checking dns misconfigurations"
    for ns in $NAMESERVERS; do
        output="$( dig AXFR "$1" @"$ns" +nostats | grep -v SOA )"
        if echo "$output" | grep -v "^;\|^$" >/dev/null; then
            records=$( echo "$output" | grep -v "^;\|^$" )
            warn "Found zone transfer: $ns"
            info "$records" \
            | awk '{ printf $1 " ==> (" $4 ") "; $1=$2=$3=$4=""; print $0; }' \
            | tr -s ' ' 
            ret_code=1
        fi
    done; return $ret_code
}

### is DNSSEC implemented
###############################################################################

dnssec_msg()
{
    [ ${1} -eq 0 ] && return
    echo ""
}

dnssec()
{
    msg "[dnssec] Running checks for compliance"
    if ! dig DNSKEY "$1" +short | grep ''; then
        warn "Failed: DNSSEC not implemented"
        return 1
    fi
}

### Mail records
### https://dmarcian.com/spf-syntax-table/
### https://gitlab.com/brn1337/mailAuthCheck
###############################################################################

spf_msg()
{
    [ ${1} -eq 0 ] && return
    echo ""
}

check_spf()
{
    _spf="$( dig TXT $1 +short @$2 | grep -i 'v=spf1' )"
    if [ -z "$_spf" ]; then
        warn "${3}No SPF for $1 in $2"
    elif echo $_spf | grep -- '-all' >/dev/null; then
        info "${3}Secure SPF for $1 in $2"
    elif echo $_spf | grep -- '~all' >/dev/null; then
        warn "${3}Partially Secure (~all) SPF for $1 in $2"
        ret_code=1
    elif echo $_spf | grep -- '+all' >/dev/null; then
        warn "${3}Insecure (+all) SPF for $1 in $ns"
        ret_code=1
    elif echo $_spf | grep -- '?all' >/dev/null; then
        warn "${3}Insecure (?all) SPF for $1 in $ns"
        ret_code=1
    fi
    spf_recur="$( echo $_spf | grep -oE "(redirect=|include:)[^ \"]*" | sed "s/include://;s/redirect=//" | sort -u )"
    for ss in ${spf_recur}; do
        check_spf ${ss} "$2" "${3}    " || ret_code=1
    done
    return $ret_code
}

spf()
{
    msg "[spf] Checking SPF record(s)"
    ret_code=0
    for ns in $NAMESERVERS; do
        check_spf "$1" "$ns" || ret_code=1
    done; return $ret_code
}

dkim_msg()
{
    [ ${1} -eq 0 ] && return
    echo ""
}

dkim()
{
    msg "[dkim] Checking if DKIM is implemented"
    ret_code=0
    for ns in $NAMESERVERS; do
        found=0
        for selector in ${1%%\.*} default dkim dkim-shared dkimpal email gamma google mail mdaemon selector selector1 selector2 selector3 selector4 selector5; do
            key=$( dig TXT "${selector}._domainkey.${1}" +short @"$ns" | grep -i "v=dkim" )
            if [ ! -z "$key" ]; then
                info "DKIM found for $1 in $ns ($selector._domainkey.${1})"
                found=1; break
            fi
        done
        if [ $found -eq 0 ]; then
            warn "No DKIM found for $1 in $ns"
            ret_code=1
        fi
    done
    return $ret_code
}

dmarc_msg()
{
    [ ${1} -eq 0 ] && return
    echo ""
}

dmarc()
{
    msg "[dmarc] Checking DMARC records"
    ret_code=0
    for ns in $NAMESERVERS; do
        _dmarc="$( dig TXT "_dmarc.${1}" +short @"$ns" | grep -i "v=dmark" )"
        if [ -z "$_dmarc" ]; then
            warn "DMARC not present for $1 in $ns"
            ret_code=1
        elif echo $_dmarc | grep "p=reject" &>/dev/null; then
            info "Secure DMARC policy (reject) for $1 in $ns"
        elif echo $_dmarc | grep "p=quarantine" &>/dev/null; then
            info "Secure DMARC policy (quarantine) for $1 in $ns"
        elif echo $_dmarc | grep "p=none" &>/dev/null; then
            warn "Insecure DMARC policy (none) for $1 in $ns"
            ret_code=1
        fi
    done; return $ret_code
}

### BGP Assessment
###############################################################################

bgp_msg()
{
    [ ${1} -eq 0 ] && return
    echo ""
}

bgp()
{
    msg "[bgp] Checking low hanging BGP misconfigurations"
    ret_code=0
    for ns in $NAMESERVERS; do
        nsip="$( dig A $ns +short )"
        assn="$assn $( whois -h whois.cymru.com "-v $nsip" | tail -n +3 | tr -d ' ' | cut -d '|' -f 1,3,7 | tr '\n' ' ' )"
    done
    if [ "$assn" = " " ]; then
        warn "Could not retrieve info from whois.cymru.com database"
        warn "check with Hurricane: https://bgp.he.net/"
        return 1
    fi
    assn="$( echo $assn | tr ' ' '\n' | sort -u | tr '\n' ' ' )"

    for asrt in $assn; do
        as="$( echo ${asrt} | cut -d '|' -f 1 )"
        sn="$( echo ${asrt} | cut -d '|' -f 2 )"
        if whois -h whois.bgpmon.net " --roa $as $sn" | grep "Not Found" &>/dev/null; then
            warn "No ROA for $sn originated by $as"
            ret_code=1
        fi
        geo="${geo} $( echo ${asrt} | cut -d '|' -f 2 | cut -d ',' -f 2 )"
    done
    
    ngeoloc="$( echo "$geo" | tr -s ' ' | sed "s/^\s//g" | tr ' ' '\n' | sort -u | wc -l )"
    case "$ngeoloc" in
        "0") 
            warn "Something went wrong, check georedundancy manually"
            ret_code=1
            ;;
        "1") 
            warn "Bad georedundancy: 1 location"
            ret_code=1
            ;;
        *)
            nasn="$( echo $assn | tr ' ' '\n' | wc -l )"
            if [ "$nasn" -gt 3 ] && [ $( expr "$nasn" / 2 ) -gt "$ngeoloc" ]; then
                warn "Ideally, you should have every 1 or 2 ASNs in different"
                warn "geographical locations. In this case we have:"
                warn "$nasn ASNs distributed on $ngeoloc locations"
                ret_code=1
            fi
    esac
    return $ret_code
}

###############################################################################
###############################################################################

usage()
{
    echo "Usage: dns-hunter.sh [-h] [-v] [-a] [-n <file>] -d DOMAIN"
    echo ""
    echo "    -h|--help          Display help and exit"
    echo "    -v|--verbose       Show verbose output"
    echo "    -a|--aggressive    Run in aggressive mode"
    echo "    -d|--domain        Specify target domain"
    echo "    -n|--file-ns       File with nameservers (new-line separated)"
    echo ""
}

# check for needed software
NEEDED="whois dig nmap expr"
if ! command -v $( echo $NEEDED ) >/dev/null; then
    err "The script needs the following binaries to work: $NEEDED"
fi

VERBOSE=0; AGGRESS=0
while [ $# -ne 0 ]; do case $1 in
    -h|--help)       usage; exit 0 ;;
    -v|--verbose)    VERBOSE=1 ;;
    -a|--aggressive) AGGRESS=1 ;;
    -d|--domain)     shift; TARGET=$1 ;;
    -n|--file-ns)    shift; NAMESERVERS="$1" ;;
    *)               usage; err "Unrecognized option $1" ;;
esac; shift; done

if [ -z $TARGET ]; then
    err "Target domain not defined (-d|--domain)"
fi

if [ -n "$NAMESERVERS" ] && [ -f "$NAMESERVERS" ]; then
    export NAMESERVERS="$( cat "$NAMESERVERS" | tr '\n' ' ' )"
else
    export NAMESERVERS=$( dig NS "$TARGET" +short | sed 's/\.$//g' | tr '\n' ' ' )
fi

if [ $AGGRESS -eq 1 ]; then
    version $TARGET
fi

checks="soa_info zone_transfer any_query glue_record dnssec spf dmarc dkim bgp"
for check in $checks; do
    if ${check} "${TARGET}"; then
        msg "No misconfiguration found"
    else
        echo 
        ${check}_msg "${VERBOSE}"
    fi; echo
done

