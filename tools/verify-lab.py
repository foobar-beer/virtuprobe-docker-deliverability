#!/usr/bin/env python3
"""
Check that the lab is actually answering what the README says it answers.

    python3 tools/verify-lab.py

Every claim in the README is a check here. Run it after `docker compose up -d`, and run it before
believing a red audit chain: a chain failing against good.mail.test is either a bug in the chain or a
lab that did not come up, and those two need opposite responses.

WHY IT PRINTS A DENOMINATOR
---------------------------
"All clear" is indistinguishable from "read nothing" unless the count is on screen. A container can
be Up with no published port at all, which happens when the bind failed at creation because
something else held the port and the container was later started rather than recreated: docker ps
shows an empty Ports column while docker inspect still lists the bindings. So the last line says how
many checks ran, and a run that reaches the end with zero checks is a failure however clean it looks.

Stdlib only, apart from dig.
"""

import json
import re
import socket
import subprocess
import time
import sys
import urllib.request

DNS = ("127.0.0.1", 11053)
SPAMD = ("127.0.0.1", 11783)
MAILPIT_SMTP = ("127.0.0.1", 11025)
MAILPIT_HTTP = "http://127.0.0.1:11080"
GREENMAIL_IMAP = ("127.0.0.1", 11143)
FIXTURES = "http://127.0.0.1:11081"
RSPAMD = "http://127.0.0.1:11333"

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{('  ' + detail) if detail else ''}")
    return ok


def dig(name, rrtype="TXT"):
    """Returns (rcode, [values]). Values keep their quotes stripped and multi-string TXT joined."""
    out = subprocess.run(
        ["dig", f"@{DNS[0]}", "-p", str(DNS[1]), "+tries=1", "+time=3", rrtype, name],
        capture_output=True, text=True, timeout=15).stdout
    rcode = "NOERROR"
    m = re.search(r"status: (\w+)", out)
    if m:
        rcode = m.group(1)
    values = []
    in_answer = False
    for line in out.splitlines():
        if line.startswith(";; ANSWER SECTION"):
            in_answer = True
            continue
        if in_answer:
            if not line.strip() or line.startswith(";;"):
                break
            parts = line.split(None, 4)
            if len(parts) >= 5:
                raw = parts[4]
                if rrtype == "TXT":
                    # dig prints each character-string quoted and space separated; a verifier joins
                    # them with nothing in between (RFC 6376 section 3.6.2.2).
                    values.append("".join(re.findall(r'"([^"]*)"', raw)))
                else:
                    values.append(raw.strip())
    return rcode, values


def wait_for_spamd(deadline_seconds=60):
    """
    Wait until spamd actually answers a REPORT, not until its port accepts.

    ⚠️ The port is useless as a readiness check here, and measured rather than assumed: on a cold
    `docker compose up` the published port accepts on the first attempt at 0.0s and spamd then RESETS
    every connection for 5.5 more seconds. Docker's userland proxy terminates the host side and
    relays, so what accepts the connection is docker-proxy and not spamd, and a check that opens a
    socket learns nothing about whether the daemon behind it has loaded its rules.

    A guard that tries once, or three times, therefore fails right after the fleet starts, which is
    exactly when somebody runs this. It reports how long it waited, because a wait that is creeping
    upwards is worth seeing rather than smoothing over.
    """
    started = time.time()
    last = None
    while time.time() - started < deadline_seconds:
        try:
            score, _mx, _rules = spamd_report(
                b"From: a@good.mail.test\r\nTo: b@example.net\r\nSubject: readiness\r\n"
                b"Date: Wed, 24 Sep 2026 09:12:04 +0200\r\n\r\nhello\r\n")
            if score is not None:
                waited = time.time() - started
                if waited > 1:
                    print(f"  (waited {waited:.1f}s for spamd to start serving)")
                return True
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
        time.sleep(1)
    print(f"  spamd did not answer a REPORT within {deadline_seconds}s, last was {last}")
    return False


def spamd_report(message: bytes):
    body = message if message.endswith(b"\n") else message + b"\r\n"
    req = b"REPORT SPAMC/1.5\r\nContent-length: %d\r\n\r\n" % len(body) + body
    s = socket.create_connection(SPAMD, timeout=30)
    s.sendall(req)
    s.shutdown(socket.SHUT_WR)
    out = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        out += chunk
    s.close()
    text = out.decode(errors="replace")
    m = re.search(r"Spam: (\w+) ; ([-\d.]+) / ([-\d.]+)", text)
    rules = re.findall(r"^\s*[-\d.]+\s+(\w+)\s", text, re.M)
    if not m:
        return None, None, rules
    return float(m.group(2)), float(m.group(3)), rules


def fetch(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.status, r.read().decode(errors="replace")


# ---------------------------------------------------------------------------- DNS
def dns_checks():
    print("\nmail-auth-dns on 11053")

    rcode, txt = dig("good.mail.test")
    spf = [t for t in txt if t.startswith("v=spf1")]
    check("good: exactly one SPF record", len(spf) == 1, f"found {len(spf)}")
    check("good: SPF ends -all", bool(spf) and spf[0].rstrip().endswith("-all"),
          spf[0] if spf else "no record")

    rcode, txt = dig("sel1._domainkey.good.mail.test")
    key = txt[0] if txt else ""
    check("good: DKIM record present", key.startswith("v=DKIM1"))
    # The drift check that matters: a 2048 bit key is split across two character-strings in the zone
    # file, so this also proves the join is happening. 392 base64 chars for the SPKI of a 2048 bit
    # key, and anything materially shorter means only the first string came back.
    p = key.split("p=", 1)[1] if "p=" in key else ""
    check("good: DKIM key rejoined to full length", len(p) == 392, f"{len(p)} base64 chars")
    check("good: DKIM key matches the committed private key", p == committed_pub(), "zone against fixtures/keys")

    rcode, txt = dig("_dmarc.good.mail.test")
    dmarc = txt[0] if txt else ""
    check("good: DMARC at p=reject", "p=reject" in dmarc, dmarc)
    check("good: DMARC has a reporting address", "rua=mailto:" in dmarc)

    rcode, txt = dig("_mta-sts.good.mail.test")
    check("good: MTA-STS TXT present", bool(txt) and txt[0].startswith("v=STSv1"))
    rcode, txt = dig("_smtp._tls.good.mail.test")
    check("good: TLS-RPT present", bool(txt) and txt[0].startswith("v=TLSRPTv1"))
    rcode, mx = dig("good.mail.test", "MX")
    check("good: MX present", len(mx) == 1, mx[0] if mx else "none")

    rcode, txt = dig("weak.mail.test")
    spf = [t for t in txt if t.startswith("v=spf1")]
    includes = spf[0].count("include:") if spf else 0
    check("weak: SPF exceeds the ten lookup limit", includes > 10, f"{includes} include mechanisms")
    check("weak: SPF softfails", bool(spf) and spf[0].rstrip().endswith("~all"))
    # Each include target has to resolve, or the fixture tests error handling while appearing to
    # test the limit.
    resolved = sum(1 for i in range(1, 12)
                   if dig(f"l{i}.weak.mail.test")[1] and dig(f"l{i}.weak.mail.test")[1][0].startswith("v=spf1"))
    check("weak: all eleven include targets resolve", resolved == 11, f"{resolved} of 11")

    rcode, txt = dig("_dmarc.weak.mail.test")
    dmarc = txt[0] if txt else ""
    check("weak: DMARC only monitoring", "p=none" in dmarc, dmarc)
    check("weak: DMARC has no reporting address", "rua=" not in dmarc)

    rcode, txt = dig("broken.mail.test")
    spf = [t for t in txt if t.startswith("v=spf1")]
    check("broken: two SPF records, a permerror", len(spf) == 2, f"found {len(spf)}")
    rcode, txt = dig("sel1._domainkey.broken.mail.test")
    key = txt[0] if txt else ""
    check("broken: DKIM key revoked, p= empty", key.rstrip().endswith("p="), key)
    rcode, mx = dig("broken.mail.test", "MX")
    check("broken: no MX", len(mx) == 0, f"{len(mx)} records")

    rcode, txt = dig("nospf.mail.test")
    check("nospf: has TXT records", len(txt) >= 3, f"{len(txt)} records")
    check("nospf: none of them is SPF", not any(t.startswith("v=spf1") for t in txt))

    rcode, txt = dig("spfall.mail.test")
    spf = [t for t in txt if t.startswith("v=spf1")]
    check("spfall: SPF authorizes everything", bool(spf) and "+all" in spf[0], spf[0] if spf else "")

    # DNSBL. Listed is a name in the zone, clean is NXDOMAIN, and those two are the whole check.
    rcode, a = dig("21.2.0.192.bl.mail.test", "A")
    check("bl: a listed address answers NOERROR with 127.0.0.2",
          rcode == "NOERROR" and a == ["127.0.0.2"], f"{rcode} {a}")
    rcode, a = dig("11.2.0.192.bl.mail.test", "A")
    check("bl: a clean address answers NXDOMAIN", rcode == "NXDOMAIN", rcode)

    # FCrDNS, three queries, because the PTR alone cannot answer it.
    rcode, ptr = dig("11.2.0.192.in-addr.arpa", "PTR")
    name = ptr[0].rstrip(".") if ptr else ""
    check("reverse: 192.0.2.11 has a PTR", name == "mail.good.mail.test", name)
    rcode, a = dig(name or "nothing.invalid", "A")
    check("reverse: the PTR name resolves back to the same address", a == ["192.0.2.11"], str(a))
    rcode, ptr = dig("21.2.0.192.in-addr.arpa", "PTR")
    stale = ptr[0].rstrip(".") if ptr else ""
    rcode2, a = dig(stale or "nothing.invalid", "A")
    check("reverse: the stale PTR fixture fails forward confirmation",
          bool(stale) and not a, f"{stale} -> {a or 'no address'}")


def committed_pub():
    """
    The base64 SPKI of the committed private key, via openssl so this tool needs no python packages.

    ⚠️ The path is passed as a file rather than piped on stdin. `openssl rsa -in -` does NOT read
    stdin, it looks for a file literally named "-" and fails with an unregistered-scheme error, and
    the empty output then made this check report a key mismatch that did not exist. Caught on the
    first run, in the safe direction, which is the only reason it was cheap.
    """
    import base64
    der = subprocess.run(
        ["openssl", "rsa", "-in", "fixtures/keys/good.mail.test.sel1.key.pem",
         "-pubout", "-outform", "DER"],
        capture_output=True).stdout
    if not der:
        raise RuntimeError("openssl produced no key, so this check cannot mean anything")
    return base64.b64encode(der).decode()


# ---------------------------------------------------------------------------- spamd
def spamd_checks():
    print("\nspamd on 11783")
    corpus = "fixtures/www/messages"

    check("rspamd is serving", wait_for_rspamd())
    if not check("spamd is serving", wait_for_spamd()):
        # Returning rather than pressing on, so the four content checks below are reported as NOT RUN
        # in the total instead of as four failures. Four failures reads as four defects in the corpus.
        return

    score, mx, rules = spamd_report(open(f"{corpus}/clean.eml", "rb").read())
    check("clean.eml scores below the threshold", score is not None and score < mx,
          f"{score} / {mx}")
    check("clean.eml has no MISSING_DATE", "MISSING_DATE" not in rules, str(sorted(set(rules))))

    score2, mx2, rules2 = spamd_report(open(f"{corpus}/no-date.eml", "rb").read())
    check("no-date.eml triggers MISSING_DATE", "MISSING_DATE" in rules2, f"{score2} / {mx2}")
    # The discriminator: the corpus has to move the score, or a content assertion proves nothing.
    check("the two differ in score", score2 != score, f"{score} against {score2}")

    score3, mx3, rules3 = spamd_report(open(f"{corpus}/spammy.eml", "rb").read())
    check("spammy.eml scores above clean.eml", score3 > score, f"{score3} against {score}")


# ---------------------------------------------------------------------------- authentication
def auth_checks():
    """
    SPF, DKIM and DMARC evaluated against the fixture zones by two engines.

    This is the section that proves the fixtures are real rather than plausible. A zone file saying
    p=reject is a string until something reads it and acts on it.
    """
    print("\nauthentication, spamd on 11783 and rspamd on 11333")

    good = "fixtures/www/messages/signed-good.eml"
    bad = "fixtures/www/messages/signed-tampered.eml"

    # ⚠️ Each engine has to be pointed at the fixture resolver or these verdicts are noise, and the
    # noise LOOKS like a verdict. Measured on this lab before the resolver was wired in: both
    # messages came back DKIM_INVALID from SpamAssassin and R_DKIM_PERMFAIL from Rspamd, because
    # neither could fetch the key, so a valid signature and a forged one were indistinguishable.
    _score, _mx, good_rules = spamd_report(open(good, "rb").read())
    _score, _mx, bad_rules = spamd_report(open(bad, "rb").read())
    check("spamd: a valid signature is DKIM_VALID", "DKIM_VALID" in good_rules, str(good_rules))
    check("spamd: a tampered body is DKIM_INVALID",
          "DKIM_INVALID" in bad_rules and "DKIM_VALID" not in bad_rules, str(bad_rules))

    good_syms, good_score, _a = rspamd_check(good, ip="192.0.2.11", sender="orders@good.mail.test")
    bad_syms, bad_score, _a = rspamd_check(bad, ip="192.0.2.11", sender="orders@good.mail.test")
    check("rspamd: a valid signature is R_DKIM_ALLOW", "R_DKIM_ALLOW" in good_syms)
    check("rspamd: a tampered body is R_DKIM_REJECT",
          "R_DKIM_REJECT" in bad_syms and "R_DKIM_ALLOW" not in bad_syms)
    check("rspamd: DKIM aligns with the From domain", "R_DKIM_ALIGNED" in good_syms)
    check("rspamd: DMARC passes on the good domain", "DMARC_POLICY_ALLOW" in good_syms)

    # SPF needs the connecting IP, which a file on disk does not carry. Rspamd takes it as a header,
    # which is how a chain supplies it too.
    allow_syms, _s, _a = rspamd_check(good, ip="192.0.2.11", sender="orders@good.mail.test")
    fail_syms, _s, _a = rspamd_check(good, ip="198.51.100.77", sender="orders@good.mail.test")
    check("rspamd: an authorized IP gives R_SPF_ALLOW", "R_SPF_ALLOW" in allow_syms)
    check("rspamd: an unauthorized IP gives R_SPF_FAIL",
          "R_SPF_FAIL" in fail_syms and "R_SPF_ALLOW" not in fail_syms)

    # ⚠️ THE FINDING THAT SHAPES EVERY CHAIN WRITTEN AGAINST THIS LAB. A forged signature barely
    # moves the score and does not change the verdict, so an assertion on either passes on a message
    # whose DKIM is broken. Measured: spamd -0.1 against 0.2, rspamd -1.0 against -0.8, and rspamd's
    # action stays "no action" for both. Only the SYMBOL discriminates. Assert on symbols.
    sa_good, _mx1, _r = spamd_report(open(good, "rb").read())
    sa_bad, _mx2, _r = spamd_report(open(bad, "rb").read())
    check("a score cannot tell a forged signature from a valid one",
          abs(sa_bad - sa_good) < 1.0,
          f"spamd moved {sa_good} to {sa_bad}, which is why chains assert on symbols")


def rspamd_check(path, ip=None, sender=None):
    """Returns (symbol names, score, action). Rspamd speaks HTTP and JSON, so a VirtuProbe chain
    needs no new protocol module for it: an HTTP probe plus HTTP_JSON_PATH reads all three."""
    body = open(path, "rb").read()
    req = urllib.request.Request(f"{RSPAMD}/checkv2", data=body, method="POST")
    if ip:
        req.add_header("IP", ip)
    if sender:
        req.add_header("From", sender)
    with urllib.request.urlopen(req, timeout=40) as r:
        d = json.load(r)
    return set(d.get("symbols", {})), d.get("score"), d.get("action")


def wait_for_rspamd(deadline_seconds=90):
    """Same reasoning as wait_for_spamd. Rspamd also has to load its rules before it can answer."""
    started = time.time()
    while time.time() - started < deadline_seconds:
        try:
            with urllib.request.urlopen(f"{RSPAMD}/ping", timeout=5) as r:
                if b"pong" in r.read():
                    waited = time.time() - started
                    if waited > 1:
                        print(f"  (waited {waited:.1f}s for rspamd)")
                    return True
        except Exception:
            pass
        time.sleep(1)
    return False


# ---------------------------------------------------------------------------- HTTP fixtures
def fixture_checks():
    print("\nfixtures on 11081")
    status, body = fetch(f"{FIXTURES}/.well-known/mta-sts.txt")
    check("MTA-STS policy served", status == 200 and "mode: enforce" in body, f"HTTP {status}")
    check("the policy names the MX", "mx: mail.good.mail.test" in body)
    status, body = fetch(f"{FIXTURES}/messages/signed-good.eml")
    check("the signed corpus is served", status == 200 and "DKIM-Signature:" in body,
          f"HTTP {status}, {len(body)} bytes")
    status, body = fetch(f"{FIXTURES}/messages/signed-tampered.eml")
    check("the tampered control is served", status == 200 and "was cancelled" in body)


# ---------------------------------------------------------------------------- corpus
def corpus_checks():
    """
    The corpus on disk, before anything is served. Not about the lab being up, and here because this
    is the one script anybody runs and a corrupted corpus is otherwise silent.
    """
    print("\ncorpus on disk")
    import glob

    files = sorted(glob.glob("fixtures/www/messages/*.eml"))
    check("the corpus is present", len(files) == 10, f"{len(files)} files")

    # ⚠️ CRLF is not cosmetic. A message on the wire uses CRLF, DKIM signs the body as CRLF, and a
    # strict reading of RFC 6376 relaxed canonicalization splits the body on CRLF. git's
    # core.autocrlf=input converts these to bare LF on commit unless .gitattributes says otherwise,
    # and then the stored bytes are not the bytes that were signed.
    lf_only = [f.split("/")[-1] for f in files
               if open(f, "rb").read().count(b"\n") > open(f, "rb").read().count(b"\r\n")]
    check("every fixture still uses CRLF", not lf_only, str(lf_only) if lf_only else "all 10")

    # The signature and its negative control, checked STRICTLY rather than with a lenient verifier.
    # dkimpy verifies the LF version too, because it normalizes line endings first, and that tolerance
    # is what makes a corrupted corpus look fine. Strict is the only reading that can tell them apart.
    for name, expected in [("signed-good.eml", True), ("signed-tampered.eml", False)]:
        got = body_hash_matches(f"fixtures/www/messages/{name}")
        check(f"{name} body hash {'matches' if expected else 'does NOT match'} its signature",
              got == expected, f"got {got}")


def body_hash_matches(path):
    """Recompute the relaxed body hash and compare it to the bh= in the signature."""
    import base64
    import hashlib

    raw = open(path, "rb").read()
    m = re.search(rb"DKIM-Signature:(.*?)\r\n(?=[A-Za-z])", raw, re.S)
    if not m:
        raise RuntimeError(f"{path} carries no DKIM-Signature")
    flat = m.group(1).replace(b"\r\n", b"").replace(b" ", b"")
    bh = re.search(rb"bh=([A-Za-z0-9+/=]+)", flat).group(1)
    body = raw.split(b"\r\n\r\n", 1)[1]
    lines = [re.sub(rb"[ \t]+", b" ", l).rstrip(b" \t") for l in body.split(b"\r\n")]
    while lines and lines[-1] == b"":
        lines.pop()
    canon = b"".join(l + b"\r\n" for l in lines) if lines else b""
    return base64.b64encode(hashlib.sha256(canon).digest()) == bh


# ---------------------------------------------------------------------------- sinks
def sink_checks():
    print("\nmailpit on 11025 and 11080, greenmail on 11143")
    marker = f"vp-verify-{__import__('uuid').uuid4().hex[:8]}"
    msg = (f"From: orders@good.mail.test\r\nTo: sink@example.net\r\n"
           f"Subject: {marker}\r\n\r\nverification\r\n")
    s = socket.create_connection(MAILPIT_SMTP, timeout=15)
    banner = s.recv(1024).decode(errors="replace")
    ok = banner.startswith("220")
    for cmd in ["EHLO verify", "MAIL FROM:<orders@good.mail.test>", "RCPT TO:<sink@example.net>", "DATA"]:
        s.sendall(cmd.encode() + b"\r\n")
        s.recv(4096)
    s.sendall(msg.encode() + b".\r\n")
    accepted = s.recv(4096).decode(errors="replace")
    s.sendall(b"QUIT\r\n")
    s.close()
    check("mailpit accepts a message", ok and accepted.startswith("250"), accepted.strip()[:60])

    status, body = fetch(f"{MAILPIT_HTTP}/api/v1/messages?limit=20")
    found = marker in body
    check("the mailpit API returns what was just sent", status == 200 and found,
          f"HTTP {status}")

    s = socket.create_connection(GREENMAIL_IMAP, timeout=15)
    banner = s.recv(1024).decode(errors="replace")
    s.sendall(b"a1 LOGOUT\r\n")
    s.close()
    check("greenmail answers an IMAP banner", "OK" in banner and "IMAP" in banner.upper(),
          banner.strip()[:60])


def main():
    print("Verifying the deliverability lab.")
    for fn in (dns_checks, corpus_checks, spamd_checks, auth_checks, fixture_checks, sink_checks):
        try:
            fn()
        except Exception as e:
            check(f"{fn.__name__} raised", False, f"{type(e).__name__}: {e}")

    total = len(PASS) + len(FAIL)
    print(f"\n{total} checks ran, {len(PASS)} passed, {len(FAIL)} failed")
    if total == 0:
        sys.exit("INCONCLUSIVE: no check ran, so this says nothing about the lab")
    if FAIL:
        print("\nfailed:")
        for name in FAIL:
            print(f"  {name}")
        sys.exit(1)
    print("The lab is answering what the README says it answers.")


if __name__ == "__main__":
    main()
