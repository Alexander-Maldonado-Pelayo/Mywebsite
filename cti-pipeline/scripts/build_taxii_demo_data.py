"""Turn a STIX bundle into a data file for medallion, the OASIS TAXII 2.1 reference server.

Usage:
    python scripts/build_taxii_demo_data.py [bundle.json] [port]

Then run the local TAXII server:
    medallion --port 5555 samples/medallion_config.json
"""

import json
import os
import sys
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
bundle_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "samples", "sample_indicator_feed.json")
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5555
out_path = os.path.join(ROOT, "samples", "taxii_server_data.json")

with open(bundle_path, encoding="utf-8") as fh:
    objects = json.load(fh)["objects"]

api_root = f"http://127.0.0.1:{port}/sector-isac/"
media_type = "application/stix+json;version=2.1"
manifest = [
    {"id": obj["id"], "date_added": obj.get("modified", obj.get("created")), "version": obj.get("modified", obj.get("created")), "media_type": media_type}
    for obj in objects
]

data = {
    "/discovery": {
        "title": "Demo sector ISAC TAXII server",
        "description": "Local TAXII 2.1 server for the CTI pipeline demo (medallion).",
        "default": api_root,
        "api_roots": [api_root],
    },
    "sector-isac": {
        "information": {
            "title": "Sector ISAC sharing group",
            "description": "Indicators and reports shared between members.",
            "versions": ["application/taxii+json;version=2.1"],
            "max_content_length": 9765625,
        },
        "status": [],
        "collections": [
            {
                "id": str(uuid.uuid5(uuid.NAMESPACE_URL, "cti-pipeline/indicator-feed")),
                "title": "Indicator feed",
                "description": "Weekly indicator digest from the ISAC (read-only for members).",
                "can_read": True,
                "can_write": False,
                "media_types": [media_type],
                "manifest": manifest,
                "objects": objects,
            },
            {
                "id": str(uuid.uuid5(uuid.NAMESPACE_URL, "cti-pipeline/member-submissions")),
                "title": "Member submissions",
                "description": "Members push their own TLP-marked intelligence here.",
                "can_read": True,
                "can_write": True,
                "media_types": [media_type],
                "manifest": [],
                "objects": [],
            },
        ],
    },
}

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
print(f"wrote {out_path}: {len(objects)} objects in 'Indicator feed', empty 'Member submissions'")
