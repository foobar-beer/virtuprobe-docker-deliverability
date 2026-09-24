#!/bin/sh
# Point SpamAssassin at the fixture resolver, then hand over to the image's own entrypoint.
#
# ⚠️ This wrapper exists because SpamAssassin's `dns_server` directive refuses a hostname. Given
# `dns_server mail-auth-dns:5353` it logs
#
#   config: invalid 'dns_server' value in /etc/spamassassin/local.cf (line 1)
#
# and then carries on with the container's default resolver, which cannot see the fixture zones. The
# consequence is not that DKIM checking stops working. It is that every DKIM verdict becomes
# meaningless while still looking like a verdict: SpamAssassin cannot fetch the key, reports
# DKIM_INVALID, and a correctly signed message is indistinguishable from a tampered one. Measured on
# this lab before the fix, both signed-good.eml and signed-tampered.eml came back DKIM_INVALID.
#
# A static IP in the compose file would also work and was rejected: it needs a fixed subnet, and a
# fixed subnet in a repo strangers clone is a collision waiting to happen with somebody's VPN or
# another compose project. Resolving the name at startup has neither problem.
set -e

RESOLVER_HOST="${VP_RESOLVER_HOST:-mail-auth-dns}"
RESOLVER_PORT="${VP_RESOLVER_PORT:-5353}"

ip=$(getent hosts "$RESOLVER_HOST" 2>/dev/null | awk '{print $1; exit}')

if [ -n "$ip" ]; then
    printf 'dns_server %s:%s\ndns_available yes\n' "$ip" "$RESOLVER_PORT" \
        > /etc/mail/spamassassin/local.cf
    echo "vp: SpamAssassin resolver set to $ip:$RESOLVER_PORT ($RESOLVER_HOST)"
else
    # Loud, and it does not invent a resolver. A DKIM verdict from a scanner that cannot reach the
    # fixture zones is worse than no verdict, so say so rather than starting quietly.
    echo "vp: WARNING could not resolve $RESOLVER_HOST." >&2
    echo "vp: DKIM and DMARC results from this container will be meaningless." >&2
    echo "vp: Content scoring is unaffected. Bring the lab up from all/ to wire the resolver in." >&2
fi

exec /root/entrypoint.sh "$@"
