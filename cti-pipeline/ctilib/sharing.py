"""Sharing: package intelligence as STIX 2.1 with TLP markings and move it over TAXII 2.1.

STIX is the language, TAXII is the transport. Handling designations (TLP) are
applied *before* anything leaves the organization, which is what NIST SP 800-150
asks for. The same TAXII helpers are used to pull the ATT&CK knowledge base and
to pull or push indicator collections on any TAXII 2.1 server.
"""

import json
from datetime import datetime, timezone

import stix2
from taxii2client.v21 import Collection, Server, as_pages

TLP = {
    "clear": stix2.v21.TLP_WHITE,   # STIX 2.1 still names TLP:CLEAR as "white"
    "green": stix2.v21.TLP_GREEN,
    "amber": stix2.v21.TLP_AMBER,
    "red": stix2.v21.TLP_RED,
}


# ---- building the shareable bundle ------------------------------------------------------


def build_share_bundle(requirement, kept_indicators, result, tlp="amber", producer="CTI Pipeline (student lab)"):
    """Return a STIX 2.1 bundle (as a dict) with TLP marking applied to every object."""
    marking = TLP[tlp]
    now = datetime.now(timezone.utc)

    identity = stix2.v21.Identity(
        name=producer,
        identity_class="organization",
        object_marking_refs=[marking.id],
    )

    # Re-emit the indicators that survived processing, stamped with the marking.
    indicators = []
    for ind in kept_indicators:
        obj = dict(ind.raw)
        obj["object_marking_refs"] = sorted(set(obj.get("object_marking_refs", [])) | {marking.id})
        obj.setdefault("confidence", ind.effective_confidence())
        obj["created_by_ref"] = identity.id
        indicators.append(obj)

    # A Note records the requirement and the prioritized behaviors, in plain text.
    top = result.ranked(10)
    note_text = (
        f"PIR for {requirement.stakeholder}: {requirement.question}\n"
        f"Adversaries tracked: {', '.join(requirement.groups)}\n"
        "Top ATT&CK behaviors: " + ", ".join(f"{h.attack_id} ({h.score})" for h in top)
    )
    report = stix2.v21.Report(
        name=f"Prioritized behaviors: {requirement.sector}",
        description=note_text,
        published=now,
        report_types=["threat-actor", "attack-pattern"],
        object_refs=[obj["id"] for obj in indicators] or [identity.id],
        created_by_ref=identity.id,
        object_marking_refs=[marking.id],
        confidence=None,
    )

    objects = [json.loads(marking.serialize()), json.loads(identity.serialize()), json.loads(report.serialize())]
    objects.extend(indicators)
    bundle = stix2.v21.Bundle(objects=objects, allow_custom=True)
    return json.loads(bundle.serialize())


def write_bundle(bundle, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)
    return path


# ---- TAXII 2.1 -------------------------------------------------------------------------


def connect(server_url, user=None, password=None):
    """Connect to a TAXII 2.1 server's discovery endpoint (e.g. https://host/taxii2/)."""
    return Server(server_url, user=user, password=password)


def list_collections(server):
    """[(collection object, api root url), ...] across every API root on the server."""
    found = []
    for api_root in server.api_roots:
        for collection in api_root.collections:
            found.append((collection, api_root.url))
    return found


def find_collection(server, title_contains):
    for collection, _ in list_collections(server):
        if title_contains.lower() in collection.title.lower():
            return collection
    raise LookupError(f"No collection whose title contains '{title_contains}'")


def open_collection(collection_url, user=None, password=None):
    """Open a collection directly by its URL (.../api-root/collections/<id>/)."""
    return Collection(collection_url, user=user, password=password)


def pull_collection(collection, per_page=1000, log=print, **filters):
    """Download every object in a collection, page by page. Returns a list of dicts."""
    objects = []
    for page in as_pages(collection.get_objects, per_request=per_page, **filters):
        objects.extend(page.get("objects", []))
        log(f"  ... {len(objects)} objects so far")
    return objects


def push_bundle(collection, bundle):
    """Upload a bundle to a writable collection. Returns the TAXII status object."""
    if not collection.can_write:
        raise PermissionError(f"Collection '{collection.title}' is read-only")
    status = collection.add_objects(bundle)
    return status
