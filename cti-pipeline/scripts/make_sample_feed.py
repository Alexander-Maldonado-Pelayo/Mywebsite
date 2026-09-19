"""Generate samples/sample_indicator_feed.json, a small STIX 2.1 feed with known flaws.

The feed deliberately mixes good indicators with expired, stale, low-confidence,
context-free and duplicate ones so the processing step has something to reject.
Dates are relative to today, so re-run this if the demo starts aging out the
"fresh" indicators:  python scripts/make_sample_feed.py
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stix2  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "sample_indicator_feed.json")


def days(n):
    return NOW + timedelta(days=n)


# ATT&CK context objects, identified by their external IDs so the pipeline can map them.
def attack_pattern(tid, name):
    return stix2.v21.AttackPattern(
        name=name,
        external_references=[{"source_name": "mitre-attack", "external_id": tid, "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"}],
    )


def intrusion_set(gid, name, aliases):
    return stix2.v21.IntrusionSet(
        name=name,
        aliases=aliases,
        external_references=[{"source_name": "mitre-attack", "external_id": gid, "url": f"https://attack.mitre.org/groups/{gid}"}],
    )


techniques = {
    "T1566.001": attack_pattern("T1566.001", "Phishing: Spearphishing Attachment"),
    "T1059.001": attack_pattern("T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "T1071.001": attack_pattern("T1071.001", "Application Layer Protocol: Web Protocols"),
    "T1078": attack_pattern("T1078", "Valid Accounts"),
    "T1105": attack_pattern("T1105", "Ingress Tool Transfer"),
    "T1027": attack_pattern("T1027", "Obfuscated Files or Information"),
}
groups = {
    "APT29": intrusion_set("G0016", "APT29", ["Cozy Bear", "Midnight Blizzard"]),
    "APT28": intrusion_set("G0007", "APT28", ["Fancy Bear", "Forest Blizzard"]),
    "Lazarus Group": intrusion_set("G0032", "Lazarus Group", ["HIDDEN COBRA"]),
}

feed_identity = stix2.v21.Identity(name="Example Sector ISAC feed", identity_class="organization")


def indicator(pattern, created, valid_until, confidence, labels, context=()):
    """Build one indicator plus its `indicates` relationships. Returns a list of objects."""
    kwargs = dict(
        pattern=pattern,
        pattern_type="stix",
        created=created,
        modified=created,
        valid_from=created,
        labels=labels,
        created_by_ref=feed_identity.id,
    )
    if valid_until:
        kwargs["valid_until"] = valid_until
    if confidence is not None:
        kwargs["confidence"] = confidence
    ind = stix2.v21.Indicator(**kwargs)
    objects = [ind]
    for target in context:
        objects.append(stix2.v21.Relationship(source_ref=ind.id, relationship_type="indicates", target_ref=target.id))
    return objects


objects = [feed_identity, *techniques.values(), *groups.values()]

# ---- good indicators: fresh, confident, with ATT&CK context -----------------------------
objects += indicator("[file:hashes.'SHA-256' = '3f5d0d6e9a1c4b2e8c7a6f5d4e3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c']",
                     days(-3), days(365), 90, ["malicious-activity"], [techniques["T1566.001"], groups["APT29"]])
objects += indicator("[domain-name:value = 'update-portal-secure.example']",
                     days(-5), days(180), 85, ["malicious-activity"], [techniques["T1071.001"], groups["APT29"]])
objects += indicator("[ipv4-addr:value = '203.0.113.42']",
                     days(-2), days(30), 80, ["malicious-activity"], [techniques["T1071.001"], groups["APT28"]])
objects += indicator("[file:hashes.'SHA-256' = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90']",
                     days(-7), days(365), 88, ["malicious-activity"], [techniques["T1059.001"], techniques["T1027"]])
objects += indicator("[url:value = 'http://198.51.100.7/stage/agent.ps1']",
                     days(-1), days(60), 75, ["malicious-activity"], [techniques["T1105"], groups["Lazarus Group"]])
objects += indicator("[email-addr:value = 'hr-benefits@payroll-notice.example']",
                     days(-4), days(90), 70, ["malicious-activity"], [techniques["T1566.001"], techniques["T1078"]])

# ---- expired: valid_until already passed -------------------------------------------------
objects += indicator("[ipv4-addr:value = '192.0.2.15']", days(-200), days(-60), 90, ["malicious-activity"], [groups["APT28"]])
objects += indicator("[domain-name:value = 'old-c2.example']", days(-150), days(-10), 85, ["malicious-activity"], [techniques["T1071.001"]])

# ---- stale: no valid_until and far older than the max age ----------------------------------
objects += indicator("[ipv4-addr:value = '192.0.2.99']", days(-400), None, 80, ["malicious-activity"], [groups["APT29"]])
objects += indicator("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']", days(-500), None, 70, ["malicious-activity"])

# ---- low confidence, or no context at all -------------------------------------------------
objects += indicator("[ipv4-addr:value = '198.51.100.200']", days(-2), days(30), 25, ["anomalous-activity"], [techniques["T1071.001"]])
objects += indicator("[domain-name:value = 'cdn-static-assets.example']", days(-3), days(30), 60, ["anomalous-activity"])  # no context -> 40
objects += indicator("[ipv4-addr:value = '203.0.113.77']", days(-1), days(30), None, ["anomalous-activity"])             # unknown conf, no context -> 30

# ---- duplicate of a good indicator -----------------------------------------------------------
objects += indicator("[ipv4-addr:value = '203.0.113.42']", days(-1), days(30), 80, ["malicious-activity"], [groups["APT28"]])

report = stix2.v21.Report(
    name="Weekly nation-state activity digest",
    published=NOW,
    report_types=["threat-report"],
    object_refs=[obj.id for obj in objects if obj.type == "indicator"],
    created_by_ref=feed_identity.id,
)
objects.append(report)

bundle = stix2.v21.Bundle(objects=objects)
with open(OUT, "w", encoding="utf-8") as fh:
    fh.write(bundle.serialize(pretty=True))
print(f"wrote {OUT} with {len(objects)} objects ({sum(1 for o in objects if o.type == 'indicator')} indicators)")
