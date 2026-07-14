# ingest_atlas.py
"""
Fetches MITRE ATLAS (Adversarial Threat Landscape for AI Systems) data,
splits each technique into register-based chunks (attack description vs.
mitigation guidance — same reasoning as the KEV module), embeds the attack
description, and stores everything in a persistent ChromaDB collection.
"""

import requests
import yaml
import chromadb
from chromadb.utils import embedding_functions

ATLAS_BASE_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6"
ATLAS_URL = f"{ATLAS_BASE_URL}/ATLAS-latest.yaml"

def fetch_atlas_catalog() -> dict:
    """Pull the current ATLAS YAML release. Returns the full parsed dict
    (top-level keys: tactics, techniques, mitigations, case-studies, relationships).

    ATLAS-latest.yaml is a git symlink in the source repo, and
    raw.githubusercontent.com serves a symlink's raw blob content (the target
    filename, e.g. "ATLAS-2026.06.yaml") instead of following it. Detect that
    case and re-fetch the actual versioned file it points to."""
    response = requests.get(ATLAS_URL, timeout=30)
    response.raise_for_status()
    atlas_data = yaml.safe_load(response.text)

    if isinstance(atlas_data, str):
        target_filename = atlas_data.strip()
        response = requests.get(f"{ATLAS_BASE_URL}/{target_filename}", timeout=30)
        response.raise_for_status()
        atlas_data = yaml.safe_load(response.text)

    return atlas_data


def inspect_one_technique(atlas_data: dict):
    """Debug helper — run this first to confirm actual field names before
    trusting build_atlas_documents(). Prints one raw technique and one raw
    mitigation so you can verify keys like 'description' actually exist."""
    techniques = atlas_data.get("techniques", {})
    mitigations = atlas_data.get("mitigations", {})

    first_technique_id = next(iter(techniques))
    first_mitigation_id = next(iter(mitigations))

    print("--- Sample technique ---")
    print(techniques[first_technique_id])
    print("\n--- Sample mitigation ---")
    print(mitigations[first_mitigation_id])
    print("\n--- Sample relationships entry ---")
    print(atlas_data.get("relationships", {}).get(first_technique_id, "No relationships found for this ID"))


def build_technique_to_mitigations(atlas_data: dict) -> dict:
    """Build a lookup: technique_id -> list of mitigation text, using the
    'mitigates' relationship (mitigation -> technique direction per the
    ATLAS data format). Returns {technique_id: ["mitigation text", ...]}.

    relationships is keyed by source object id (mitigation, case-study, ...),
    and each 'mitigates' entry is a list of relationship dicts shaped like
    {source, target, relationship-type, description} — target is the
    technique id, description is the relationship-specific mitigation text."""
    relationships = atlas_data.get("relationships", {})
    mitigations = atlas_data.get("mitigations", {})

    technique_to_mitigations = {}

    for mitigation_id, rel_entry in relationships.items():
        if not isinstance(rel_entry, dict):
            continue
        mitigation_obj = mitigations.get(mitigation_id)
        if not mitigation_obj:
            continue

        fallback_text = mitigation_obj.get("description", mitigation_obj.get("name", ""))

        for mitigates_rel in rel_entry.get("mitigates", []):
            technique_id = mitigates_rel.get("target")
            if not technique_id:
                continue
            mitigation_text = mitigates_rel.get("description") or fallback_text
            technique_to_mitigations.setdefault(technique_id, []).append(mitigation_text)

    return technique_to_mitigations


def build_atlas_documents(atlas_data: dict) -> tuple[list[str], list[str], list[dict]]:
    """Convert ATLAS techniques into (ids, embed_texts, metadatas) for ChromaDB.

    Register split, same reasoning as KEV/MITRE-ATT&CK design earlier:
    - embed_texts  -> attack-style description only (what gets searched)
    - metadatas    -> mitigation text + static facts (rides along, not searched)
    """
    techniques = atlas_data.get("techniques", {})
    technique_to_mitigations = build_technique_to_mitigations(atlas_data)

    ids = []
    embed_texts = []
    metadatas = []

    for technique_id, technique in techniques.items():
        name = technique.get("name", "")
        description = technique.get("description", "")

        # Skip deprecated/incomplete entries rather than embedding empty text
        if not description:
            continue

        embed_text = f"{name}: {description}"

        mitigation_texts = technique_to_mitigations.get(technique_id, [])
        mitigation_combined = "\n".join(mitigation_texts) if mitigation_texts else "No documented mitigation."

        ids.append(technique_id)
        embed_texts.append(embed_text)
        metadatas.append({
            "technique_id": technique_id,
            "technique_name": name,
            "maturity": technique.get("maturity", ""),
            "mitigation": mitigation_combined,
        })

    return ids, embed_texts, metadatas


def load_atlas_into_chroma(ids, embed_texts, metadatas, collection_name="mitre_atlas"):
    """Upsert ATLAS technique entries into a persistent ChromaDB collection.
    Same mechanics as load_kev_into_chroma — connection/model cost paid once,
    upsert is idempotent by technique_id."""
    client = chromadb.PersistentClient(path="./data/chroma_db")

    embedder = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )

    collection = client.get_or_create_collection(
        name=collection_name,
        embedding_function=embedder,
    )

    collection.upsert(
        ids=ids,
        documents=embed_texts,
        metadatas=metadatas,
    )

    return collection


def remove_stale_atlas(collection, ids):
    """Same stale-entry cleanup logic as KEV — separate, explicit,
    only run during a scheduled refresh, never inside the upsert path."""
    response = collection.get(include=[])
    all_ids = response.get("ids", [])

    stored_set = set(all_ids)
    fresh_set = set(ids)
    stale_ids = stored_set - fresh_set

    if stale_ids:
        print(f"Found {len(stale_ids)} stale ATLAS IDs, removing.")
        collection.delete(ids=list(stale_ids))
    else:
        print("No stale ATLAS IDs. Database is up to date!")

    return len(stale_ids)


if __name__ == "__main__":
    print("Starting MITRE ATLAS to ChromaDB ingest pipeline...")

    atlas_data = fetch_atlas_catalog()
    # Uncomment this once, first run, to verify field names before trusting the rest:
    # inspect_one_technique(atlas_data)

    ids, embed_texts, metadatas = build_atlas_documents(atlas_data)
    load_atlas_into_chroma(ids=ids, embed_texts=embed_texts, metadatas=metadatas)

    print("\n[SUCCESS] Ingest pipeline complete!")
    print(f"Loaded {len(ids)} ATLAS techniques into the ChromaDB collection.")