"""Sharing: package intelligence as STIX 2.1 with TLP markings and move it over TAXII 2.1.

STIX is the language, TAXII is the transport. Handling designations (TLP) are
applied *before* anything leaves the organization, which is what NIST SP 800-150
asks for.

The TAXII 2.1 client below is written with only the standard library. TAXII is
just HTTPS + JSON with two special media types, so the whole protocol fits in a
few dozen lines: discovery -> API roots -> collections -> objects (paged) and a
POST of a bundle to add objects. The same helpers pull the ATT&CK knowledge base
and pull or push indicator collections on any TAXII 2.1 server.
"""

import base64
import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import stix2

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


# ---- TAXII 2.1 (standard library only) ----------------------------------------------------

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
TIMEOUT_SECONDS = 60


class TaxiiClient:
    """Minimal HTTP helper: sets the TAXII headers and optional basic auth."""

    def __init__(self, user=None, password=None):
        self.headers = {"Accept": TAXII_MEDIA_TYPE}
        if user:
            token = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"

    def get(self, url, params=None):
        if params:
            url = url + "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        request = urllib.request.Request(url, headers=self.headers)
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return json.load(response)

    def post(self, url, body):
        data = json.dumps(body).encode()
        headers = dict(self.headers, **{"Content-Type": TAXII_MEDIA_TYPE})
        request = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return json.load(response)


class TaxiiCollection:
    """One collection on an API root: knows its URL and how to read or write objects."""

    def __init__(self, client, api_root_url, info):
        self.client = client
        self.api_root_url = api_root_url
        self.id = info["id"]
        self.title = info.get("title", self.id)
        self.can_read = bool(info.get("can_read"))
        self.can_write = bool(info.get("can_write"))
        self.url = urllib.parse.urljoin(api_root_url, f"collections/{self.id}/")

    def get_objects(self, limit=None, added_after=None):
        """Yield pages of objects, following TAXII's `more`/`next` pagination."""
        params = {"limit": limit, "added_after": added_after}
        while True:
            page = self.client.get(self.url + "objects/", params)
            yield page.get("objects", [])
            if not page.get("more") or not page.get("next"):
                return
            params = {"limit": limit, "added_after": added_after, "next": page["next"]}

    def add_objects(self, bundle):
        """POST a STIX bundle. Returns the TAXII status resource as a dict."""
        return self.client.post(self.url + "objects/", bundle)


class TaxiiServer:
    """Discovery endpoint (e.g. https://host/taxii2/) plus the API roots it advertises."""

    def __init__(self, url, client):
        self.url = url
        self.client = client
        info = client.get(url)
        self.title = info.get("title", url)
        self.api_roots = [urllib.parse.urljoin(url, root) for root in info.get("api_roots", [])]

    def collections(self):
        found = []
        for api_root in self.api_roots:
            for info in self.client.get(api_root + "collections/").get("collections", []):
                found.append((TaxiiCollection(self.client, api_root, info), api_root))
        return found


def connect(server_url, user=None, password=None):
    """Connect to a TAXII 2.1 server's discovery endpoint."""
    if not server_url.endswith("/"):
        server_url += "/"
    return TaxiiServer(server_url, TaxiiClient(user, password))


def list_collections(server):
    """[(TaxiiCollection, api root url), ...] across every API root on the server."""
    return server.collections()


def find_collection(server, title_contains):
    for collection, _ in list_collections(server):
        if title_contains.lower() in collection.title.lower():
            return collection
    raise LookupError(f"No collection whose title contains '{title_contains}'")


def open_collection(collection_url, user=None, password=None):
    """Open a collection directly by its URL (.../api-root/collections/<id>/)."""
    if not collection_url.endswith("/"):
        collection_url += "/"
    api_root_url, _, collection_id = collection_url.rstrip("/").rpartition("/")
    api_root_url = api_root_url[: -len("collections")] if api_root_url.endswith("collections") else api_root_url + "/"
    return TaxiiCollection(TaxiiClient(user, password), api_root_url, {"id": collection_id, "can_read": True, "can_write": True})


def pull_collection(collection, per_page=1000, log=print, **filters):
    """Download every object in a collection, page by page. Returns a list of dicts."""
    objects = []
    for page in collection.get_objects(limit=per_page, **filters):
        objects.extend(page)
        log(f"  ... {len(objects)} objects so far")
    return objects


def push_bundle(collection, bundle):
    """Upload a bundle to a writable collection. Returns the TAXII status dict."""
    if not collection.can_write:
        raise PermissionError(f"Collection '{collection.title}' is read-only")
    return collection.add_objects(bundle)
