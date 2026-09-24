#!/usr/bin/env python3
"""
Generate the DKIM key pairs and the signed .eml corpus.

The outputs are COMMITTED, so nobody needs to run this to use the lab. Run it only to change a
fixture or to rotate the test keys, and commit what it writes.

WHY IT DEPENDS ON dkimpy RATHER THAN SIGNING BY HAND
----------------------------------------------------
These fixtures exist to be the reference a DKIM verifier is measured against. A fixture produced by
a signer written by whoever also writes the verifier is worth nothing: the two agree on the same
misreading of RFC 6376, every test passes, and the bug ships. Canonicalization is exactly where two
careful readings differ by one byte, so the signature has to come from an implementation that was
not written here.

    python3 -m venv .venv && .venv/bin/pip install dkimpy cryptography
    .venv/bin/python tools/make-dkim-fixtures.py

THE PRIVATE KEYS ARE DELIBERATELY PUBLIC
----------------------------------------
They sign mail for domains under .test, which RFC 2606 reserves and which never routes. They are
committed so the corpus is reproducible. Never use them for anything else.
"""

import pathlib
import subprocess
import sys

try:
    import dkim
except ImportError:
    sys.exit("dkimpy is required, see the module docstring")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = pathlib.Path(__file__).resolve().parent.parent
KEYS = ROOT / "fixtures" / "keys"
MSGS = ROOT / "fixtures" / "www" / "messages"

# (domain, selector, key size). weak.mail.test gets 1024 bits on purpose: it is under what Google
# recommends and a verifier should report it as a finding rather than merely verifying it.
IDENTITIES = [
    ("good.mail.test", "sel1", 2048),
    ("weak.mail.test", "weak1", 1024),
]


def keypair(domain, selector, bits):
    """Read the committed key, or mint one when it is absent. Never silently replace one."""
    path = KEYS / f"{domain}.{selector}.key.pem"
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        print(f"  reusing {path.name} ({key.key_size} bits)")
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        path.chmod(0o600)
        print(f"  minted {path.name} ({bits} bits)")

    der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    import base64
    return key, base64.b64encode(der).decode()


def sign(message, domain, selector, key_pem, canon=(b"relaxed", b"relaxed")):
    """
    relaxed/relaxed, rsa-sha256, which is what almost everything sends.

    The h= list names From, To, Subject, Date and Message-ID. Not Received, which a relay adds after
    signing, and not Content-Type, so a fixture stays valid if its MIME wrapper is ever adjusted.
    """
    header = dkim.sign(
        message=message,
        selector=selector.encode(),
        domain=domain.encode(),
        privkey=key_pem,
        canonicalize=canon,
        include_headers=[b"from", b"to", b"subject", b"date", b"message-id"])
    return header + message


def verify(raw, domain, selector, pubkey_b64):
    """
    Verify with dkimpy, resolving the key from the value we are about to publish in the zone rather
    than over DNS. That way this checks the SIGNATURE and the KEY TOGETHER, so a fixture whose zone
    entry does not match its signature cannot pass here and fail in the lab.
    """
    record = f"v=DKIM1; k=rsa; p={pubkey_b64}".encode()

    def dnsfunc(name, timeout=5):
        # dkimpy hands the name over as bytes.
        asked = (name.decode() if isinstance(name, bytes) else name).rstrip(".") + "."
        expected = f"{selector}._domainkey.{domain}."
        if asked != expected:
            raise AssertionError(f"unexpected lookup {asked}, wanted {expected}")
        return record

    return dkim.verify(raw, dnsfunc=dnsfunc)


BODY_CLEAN = (
    "Hello,\r\n"
    "\r\n"
    "Your order 4471 has shipped and should arrive on Thursday.\r\n"
    "\r\n"
    "Track it here: https://good.mail.test/orders/4471\r\n"
    "\r\n"
    "To stop receiving these, use the unsubscribe link in your mail client.\r\n"
)


def message(headers, body=BODY_CLEAN):
    return ("".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n" + body).encode()


COMMON = [
    ("From", "Orders <orders@good.mail.test>"),
    ("To", "customer@example.net"),
    ("Subject", "Your order has shipped"),
    ("Date", "Wed, 24 Sep 2026 09:12:04 +0200"),
    ("Message-ID", "<8f3a1c7e-5b21-4d0a-9e77-2ab4c1d90f31@good.mail.test>"),
    ("MIME-Version", "1.0"),
    ("Content-Type", "text/plain; charset=UTF-8"),
]


def main():
    keys = {}
    print("keys:")
    for domain, selector, bits in IDENTITIES:
        key, pub = keypair(domain, selector, bits)
        pem = (KEYS / f"{domain}.{selector}.key.pem").read_bytes()
        keys[(domain, selector)] = (pem, pub)

    print("\nmessages:")
    written = {}

    # A correctly signed message. Everything downstream measures against this one.
    raw = sign(message(COMMON), "good.mail.test", "sel1", keys[("good.mail.test", "sel1")][0])
    written["signed-good.eml"] = raw

    # The negative control, and the single most important file here. Without a message whose
    # signature must FAIL, a verifier that returns pass unconditionally passes every other test in
    # the corpus. One character of the body changes after signing, which is what a mail-in-transit
    # modification looks like.
    tampered = raw.replace(b"order 4471 has shipped", b"order 4471 was cancelled")
    assert tampered != raw, "the tamper anchor is no longer in the body"
    written["signed-tampered.eml"] = tampered

    # Signed by a 1024 bit key. Verifies, and the key length is a finding.
    weak = sign(
        message([(k, v.replace("good.mail.test", "weak.mail.test")) for k, v in COMMON]),
        "weak.mail.test", "weak1", keys[("weak.mail.test", "weak1")][0])
    written["signed-weak-key.eml"] = weak

    # Unsigned, otherwise identical to signed-good. The control that says a difference in a verifier
    # result came from the signature rather than from the message.
    written["clean.eml"] = message(COMMON)

    # Each of the rest exists to move exactly one assertion.
    written["no-date.eml"] = message([h for h in COMMON if h[0] != "Date"])
    written["no-message-id.eml"] = message([h for h in COMMON if h[0] != "Message-ID"])

    written["unsubscribe-oneclick.eml"] = message(COMMON + [
        ("List-Unsubscribe", "<https://good.mail.test/u/8f3a1c7e>, <mailto:unsub@good.mail.test>"),
        ("List-Unsubscribe-Post", "List-Unsubscribe=One-Click"),
    ])
    written["unsubscribe-mailto-only.eml"] = message(COMMON + [
        ("List-Unsubscribe", "<mailto:unsub@good.mail.test>"),
    ])

    written["image-only.eml"] = message(
        [(k, "text/html; charset=UTF-8" if k == "Content-Type" else v) for k, v in COMMON],
        '<html><body><a href="https://good.mail.test/o/4471">'
        '<img src="https://good.mail.test/i/hero.png" width="600" height="400" alt=""></a>'
        '</body></html>\r\n')

    written["spammy.eml"] = message(
        [(k, "CONGRATULATIONS!!! You have WON a FREE prize" if k == "Subject" else v)
         for k, v in COMMON],
        "ACT NOW!!! This is a LIMITED TIME offer, click here to CLAIM YOUR FREE MONEY:\r\n"
        "http://192.0.2.99/claim?id=4471\r\n"
        "\r\n"
        "100% GUARANTEED, no credit check, RISK FREE, satisfaction or your money back!!!\r\n"
        "Viagra Cialis cheap meds no prescription needed.\r\n")

    for name, raw_bytes in sorted(written.items()):
        (MSGS / name).write_bytes(raw_bytes)
        print(f"  {name} ({len(raw_bytes)} bytes)")

    print("\nverification, against the key value the zone publishes:")
    checks = [
        ("signed-good.eml", "good.mail.test", "sel1", True),
        ("signed-tampered.eml", "good.mail.test", "sel1", False),
        ("signed-weak-key.eml", "weak.mail.test", "weak1", True),
    ]
    failures = 0
    for name, domain, selector, expected in checks:
        pub = keys[(domain, selector)][1]
        got = verify(written[name], domain, selector, pub)
        ok = got == expected
        failures += 0 if ok else 1
        print(f"  {name:28s} verify={got!s:5s} expected={expected!s:5s} {'ok' if ok else 'MISMATCH'}")
    print(f"  {len(checks)} checked, {failures} mismatched")
    if failures:
        sys.exit("fixture verification failed, nothing is trustworthy until this is clean")

    print("\npaste these into mail-auth-dns/zones:")
    for (domain, selector), (_pem, pub) in keys.items():
        print(f"  {selector}._domainkey.{domain}  ->  v=DKIM1; k=rsa; p={pub}")


if __name__ == "__main__":
    main()
