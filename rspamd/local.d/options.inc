# Point Rspamd at the fixture resolver, so its SPF, DKIM and DMARC results are about the fixture
# zones rather than about public DNS.
#
# ⚠️ Without this the results look fine and mean nothing. Measured on this lab: with the default
# resolver, signed-good.eml and signed-tampered.eml BOTH came back R_DKIM_PERMFAIL, because Rspamd
# cannot resolve sel1._domainkey.good.mail.test and a key it cannot fetch is a permanent failure. So
# a valid signature and a forged one were indistinguishable. With the resolver wired in, the same two
# messages give R_DKIM_ALLOW and R_DKIM_REJECT.
#
# Unlike SpamAssassin's dns_server, this accepts a hostname, so no static IP is needed.
dns {
  nameserver = ["mail-auth-dns:5353"];
  timeout = 3s;
  retransmits = 2;
}
