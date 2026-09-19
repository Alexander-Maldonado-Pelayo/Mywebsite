"""Collection: fetch the MITRE ATT&CK knowledge base and answer questions about it.

The knowledge base is pulled from MITRE's official TAXII 2.1 server. If that
server is unreachable (some campus and lab networks block it), the same STIX
bundle is downloaded from MITRE's GitHub mirror instead. Either way the file
is cached locally so the pipeline only downloads it once.
"""

import json
import os
import urllib.request

import stix2
from mitreattack.stix20 import MitreAttackData

ATTACK_TAXII_SERVER = "https://attack-taxii.mitre.org/taxii2/"
ATTACK_GITHUB_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_PATH = os.path.join("data", "enterprise-attack.json")


def download_attack(path=DEFAULT_PATH, prefer_taxii=True, log=print):
    """Make sure the ATT&CK bundle exists at `path`. Returns (path, source)."""
    if os.path.exists(path):
        return path, "cached"

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    if prefer_taxii:
        try:
            from .sharing import connect, find_collection, pull_collection

            log(f"  Connecting to {ATTACK_TAXII_SERVER} ...")
            server = connect(ATTACK_TAXII_SERVER)
            collection = find_collection(server, "Enterprise ATT&CK")
            objects = pull_collection(collection, log=log)
            bundle = {"type": "bundle", "id": stix2.v21.Bundle().id, "objects": objects}
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(bundle, fh)
            return path, "taxii"
        except Exception as exc:  # noqa: BLE001 - any network failure falls back
            log(f"  TAXII download failed ({exc.__class__.__name__}: {exc}).")
            log("  Falling back to MITRE's GitHub mirror.")

    urllib.request.urlretrieve(ATTACK_GITHUB_URL, path)
    return path, "github"


class AttackKnowledgeBase:
    """Thin wrapper around MitreAttackData with the lookups this pipeline needs."""

    def __init__(self, path=DEFAULT_PATH):
        self.data = MitreAttackData(path)

    # ---- metadata -------------------------------------------------------

    def version(self):
        collections = self.data.src.query([stix2.Filter("type", "=", "x-mitre-collection")])
        return collections[0].get("x_mitre_version", "unknown") if collections else "unknown"

    # ---- adversary groups -------------------------------------------------

    def find_group(self, name_or_id):
        """Resolve 'APT29', 'G0016' or an alias like 'Cozy Bear' to a group object."""
        query = name_or_id.strip()
        if query.upper().startswith("G") and query[1:].isdigit():
            group = self.data.get_object_by_attack_id(query.upper(), "intrusion-set")
            if group and not self._is_retired(group):
                return group
        for group in self.data.get_objects_by_name(query, "intrusion-set"):
            if not self._is_retired(group):
                return group
        for group in self.data.get_groups_by_alias(query):
            if not self._is_retired(group):
                return group
        return None

    def attack_id(self, stix_object):
        return self.data.get_attack_id(stix_object["id"])

    def techniques_for_group(self, group):
        """Techniques the group is documented to use directly. {T-id: technique}."""
        techniques = {}
        for item in self.data.get_techniques_used_by_group(group["id"]):
            technique = item["object"]
            if self._is_retired(technique):
                continue
            techniques[self.attack_id(technique)] = technique
        return techniques

    def software_for_group(self, group):
        return sorted(
            item["object"]["name"]
            for item in self.data.get_software_used_by_group(group["id"])
            if not self._is_retired(item["object"])
        )

    # ---- techniques ---------------------------------------------------------

    def technique_by_id(self, attack_id):
        technique = self.data.get_object_by_attack_id(attack_id, "attack-pattern")
        if technique and not self._is_retired(technique):
            return technique
        return None

    def tactics_of(self, technique):
        return [phase["phase_name"] for phase in technique.get("kill_chain_phases", [])]

    def mitigations_for(self, technique):
        """[(M-id, name), ...] for every mitigation that addresses the technique."""
        results = []
        for item in self.data.get_mitigations_mitigating_technique(technique["id"]):
            mitigation = item["object"]
            if not self._is_retired(mitigation):
                results.append((self.attack_id(mitigation), mitigation["name"]))
        return results

    def detections_for(self, technique):
        """Names of the detection strategies (or legacy data components) for a technique."""
        names = [
            item["object"]["name"]
            for item in self.data.get_detection_strategies_detecting_technique(technique["id"])
        ]
        if not names:  # ATT&CK releases before v18 used data components instead
            names = [
                item["object"]["name"]
                for item in self.data.get_datacomponents_detecting_technique(technique["id"])
            ]
        return sorted(set(names))

    # ---- helpers ----------------------------------------------------------------

    @staticmethod
    def _is_retired(stix_object):
        return bool(stix_object.get("revoked") or stix_object.get("x_mitre_deprecated"))
