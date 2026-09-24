# VirtuProbe Deliverability Lab

Targets for testing email deliverability with [VirtuProbe Studio](https://virtuprobe.studio). Clone
it, bring it up, and every authentication record an audit looks at is already there, configured
correctly on one domain and broken in a specific way on each of the others.

```bash
cd all && docker compose up -d
python3 tools/verify-lab.py
```

Five containers, about a minute on a cold start. Nothing here reaches the internet and nothing needs
an account anywhere.

## Why the DNS server is the point

Anyone can score a message against SpamAssassin. What is hard to arrange is a domain whose SPF, DKIM
and DMARC records are *known*, so that a test has a right answer to be measured against.

That is what this lab is for. A chain run against `good.mail.test` must pass, and a chain run against
`broken.mail.test` must fail, and it must fail naming the record it came from. A test with no fixture
can only report what it found; a test with one can be wrong, which is the only way to find out
whether it works.

## Ports

An `11xxx` block, so this runs alongside
[virtuprobe-docker](https://github.com/foobar-beer/virtuprobe-docker) without a collision.

| Service | Host port | What it is |
|---|---|---|
| `mail-auth-dns` | `11053` udp and tcp | CoreDNS, authoritative for the fixture domains, forwarding everything else |
| `spamd` | `11783` | SpamAssassin, for content scoring |
| `mailpit` | `11025` SMTP, `11080` HTTP | A sink that hands back the message exactly as it arrived |
| `greenmail` | `11143` IMAP, `11026` SMTP | So the read-it-back-over-IMAP half of a test works locally |
| `fixtures` | `11081` HTTP | The `.eml` corpus and the MTA-STS policy file |

Each service also has its own directory with a single-service compose file, if you only want one.

## The fixture domains

All under `.test`, which RFC 2606 reserves, with addresses from the RFC 5737 documentation range.
Nothing here can route anywhere real.

| Domain | State |
|---|---|
| `good.mail.test` | Everything correct. SPF ending `-all`, a valid 2048-bit DKIM key, DMARC at `p=reject` with reporting and strict alignment, MTA-STS, TLS-RPT, BIMI, an MX whose reverse DNS confirms forward |
| `weak.mail.test` | Everything present and nothing enforcing. SPF with eleven lookups, which is one over the RFC 7208 limit and therefore a permerror. DMARC at `p=none` with no reporting address. A 1024-bit DKIM key. No MTA-STS |
| `broken.mail.test` | Two conflicting SPF records. A DKIM selector publishing an empty `p=`, which means the key is revoked. A DMARC record with two syntax errors. No MX. An MTA-STS record with no policy behind it |
| `nospf.mail.test` | Three vendor verification tokens in TXT and no SPF among them |
| `spfall.mail.test` | SPF `+all`, which authorizes the entire internet, plus `?all` on a subdomain |
| `bl.mail.test` | A blacklist. `192.0.2.21` and `192.0.2.30` are listed, `192.0.2.11` is not |
| `2.0.192.in-addr.arpa` | Reverse DNS. One address confirms forward, one points at a name that no longer exists, one points at a name belonging to a different address, one has no PTR |

`weak.mail.test` is the interesting one. It is the state most real domains are actually in, and it is
the hardest case for an audit to be useful about, because a check that asks "is SPF configured, is
DKIM configured, is DMARC configured" reports all three present and the domain is still spoofable.

The reverse zone earns its place the same way. A PTR that resolves looks healthy on its own, and only
querying the name back and comparing the address catches the two broken cases, which is why a
forward-confirmed reverse DNS check is three queries rather than one.

## Pointing VirtuProbe at it

The audit chains in the **Email Deliverability** library collection default to these values, so a
fresh import runs with nothing filled in:

| Variable | Value |
|---|---|
| `resolver` | `127.0.0.1` |
| `resolver_port` | `11053` |
| `domain` | `good.mail.test` |
| `dkim_selector` | `sel1` |
| `spamd_host` | `127.0.0.1` |
| `spamd_port` | `11783` |
| `blacklist_zone` | `bl.mail.test` |

Change `domain` to one of the broken fixtures and the same chain should fail. Change `resolver` to a
real one and `domain` to your own, and the same chain audits production. That is the whole difference
between the two, and it is why the resolver forwards anything it is not authoritative for.

## The message corpus

Served at `http://127.0.0.1:11081/messages/`, and also on disk under `fixtures/www/messages/`. Paste
one into a probe, or fetch it with an HTTP step and pass it on with `{{variables}}`.

| File | Exists to |
|---|---|
| `clean.eml` | Be the baseline. Unsigned, correct headers, scores near zero |
| `signed-good.eml` | Verify. Signed by `sel1._domainkey.good.mail.test`, relaxed/relaxed, rsa-sha256 |
| `signed-tampered.eml` | **Fail.** Same signature, one phrase of the body changed afterwards |
| `signed-weak-key.eml` | Verify against a 1024-bit key, so key length is a finding rather than a failure |
| `no-date.eml` | Trigger `MISSING_DATE` |
| `no-message-id.eml` | Trigger `MISSING_MID` |
| `unsubscribe-oneclick.eml` | Satisfy RFC 8058, which Gmail and Yahoo require of bulk senders |
| `unsubscribe-mailto-only.eml` | Not satisfy it, while looking like it does |
| `image-only.eml` | Be an HTML message with one image and no text |
| `spammy.eml` | Score well over the threshold |

`signed-tampered.eml` is the most important file here. Without a message whose signature must fail, a
verifier that returns pass unconditionally passes every other test in the corpus.

## Verifying the lab came up

```bash
python3 tools/verify-lab.py
```

43 checks, one per claim this README makes, and it prints the count, because "all clear" and "read
nothing" look identical without it.

Two things it handles that a hand-rolled check usually does not.

**It waits for SpamAssassin to start serving, rather than for its port to open.** Measured on a cold
`docker compose up`: the published port accepts on the first attempt at 0.0s and spamd then resets
every connection for 5.5 more seconds. Docker's userland proxy terminates the host side and relays, so
what accepts the connection is the proxy and not spamd. A check that opens a socket learns nothing
about whether the daemon behind it has loaded its rules, and a guard that tries once fails right after
the fleet starts, which is exactly when anybody runs it.

**It checks the corpus on disk, not only the lab.** A message on the wire uses CRLF, DKIM signs the
body as CRLF, and git's `core.autocrlf=input` converts these files to bare LF on commit unless
`.gitattributes` says otherwise. The signature then does not cover the bytes on disk. Measured while
building this repo: a strict recomputation of the relaxed body hash mismatches on the converted file,
while dkimpy verifies it anyway because it normalizes line endings first, and that tolerance is what
makes the corruption silent. The check is strict for exactly that reason.

**It tells a container that is `Up` with no published port from one that is working.** That happens
when the bind failed at creation because something else held the port and the container was later
started rather than recreated: `docker ps` shows an empty Ports column while `docker inspect` still
lists the bindings you configured. The fix is `docker compose up -d --force-recreate <service>`, and
a plain restart will not do it.

Needs `dig` and `openssl`. No Python packages.

## Three places this lab is not production

Worth reading before treating a green run as a prediction.

**The MTA-STS policy is served over plain HTTP.** RFC 8461 requires HTTPS from `mta-sts.<domain>`, and
a trusted certificate chain for a `.test` name is not something anybody should have to arrange to try
a lab. The DNS half of the check, the `_mta-sts` TXT record, is exactly faithful. The policy fetch is
at `http://127.0.0.1:11081/.well-known/mta-sts.txt`.

**GreenMail has no spam filter and writes no `Authentication-Results` header.** A real inbox placement
test compares the inbox against the junk folder and reads the receiving provider's own verdict on your
authentication out of that header. Neither exists here, so this container exercises the mechanics of
such a test and cannot exercise its finding. For that you need mailboxes at real providers, which is
the one part of this nobody can ship you.

**SpamAssassin runs with an unprimed Bayes database.** That is what makes the scores here
reproducible, since a trained Bayes drifts as it learns and a content assertion that was green
yesterday goes red for a reason nobody changed. It also means these scores are lower than a
production filter would give, so read a passing score as "this message has no structural faults"
rather than as a prediction of where it will land.

## The DKIM keys are deliberately public

`fixtures/keys/` holds the private keys that sign the corpus, in the clear. They sign mail for
domains under `.test` that cannot route, and they are committed so the corpus is reproducible and so
the published key in the zone can be checked against the key that actually signed. Never use them for
anything else.

`tools/verify-lab.py` compares the `p=` value in the zone against the committed key on every run, so
the two cannot drift apart unnoticed.

## Regenerating the corpus

Only needed to change a fixture or rotate the test keys. The outputs are committed.

```bash
python3 -m venv .venv && .venv/bin/pip install dkimpy cryptography
.venv/bin/python tools/make-dkim-fixtures.py
```

It signs with **dkimpy** rather than with a signer written here, and that is deliberate. These
fixtures exist to be the reference a DKIM verifier is measured against, and a fixture produced by a
signer written by whoever also writes the verifier is worth nothing: the two agree on the same
misreading of RFC 6376, every test passes, and the bug ships. DKIM canonicalization is exactly where
two careful readings of the spec differ by one byte.

The script verifies its own output before writing the zone values, and refuses to finish if
`signed-good.eml` does not verify or `signed-tampered.eml` does.

## License

MIT. See LICENSE.
