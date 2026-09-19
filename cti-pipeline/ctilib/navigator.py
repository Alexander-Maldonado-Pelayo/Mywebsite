"""Dissemination: write an ATT&CK Navigator layer (the colored matrix heat map).

Open https://mitre-attack.github.io/attack-navigator/ , choose
"Open Existing Layer" -> "Upload from local", and pick the JSON this writes.
"""

import json

from mitreattack.navlayers import Layer

LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.1.0"


def build_layer(result, name, attack_version, description=""):
    max_score = max((hit.score for hit in result.hits.values()), default=1)
    techniques = []
    for hit in result.hits.values():
        who = ", ".join(sorted(hit.groups)) or "no tracked group"
        comment = f"Used by: {who}"
        if hit.indicator_count:
            comment += f" | {hit.indicator_count} live indicator(s)"
        techniques.append(
            {
                "techniqueID": hit.attack_id,
                "score": hit.score,
                "comment": comment,
                "enabled": True,
                "showSubtechniques": hit.is_subtechnique,
            }
        )

    layer_dict = {
        "name": name,
        "description": description,
        "domain": "enterprise-attack",
        "versions": {"layer": LAYER_VERSION, "attack": attack_version, "navigator": NAVIGATOR_VERSION},
        "techniques": techniques,
        "gradient": {"colors": ["#fff7e6", "#ff8c00", "#8b0000"], "minValue": 0, "maxValue": max_score},
        "legendItems": [
            {"label": "Used by one tracked adversary", "color": "#fff7e6"},
            {"label": f"Used by all tracked adversaries / live indicators (score {max_score})", "color": "#8b0000"},
        ],
        "layout": {"layout": "side", "showID": True, "showName": True},
        "sorting": 3,
    }
    return Layer(init_data=layer_dict)


def write_layer(result, path, name, attack_version, description=""):
    layer = build_layer(result, name, attack_version, description)
    # Layer.to_file() writes UTF-16; plain UTF-8 JSON is friendlier for git and diff tools,
    # and the Navigator reads it fine. Building the Layer first validates the structure.
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(layer.to_dict(), fh, indent=2)
    return path
