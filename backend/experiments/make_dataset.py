"""Generate the independent held-out evaluation set from the knowledge graph.

Every label is read from the graph records themselves (never from the assistant's
answers) and the sampling is seeded, so the same graph always gives the same set.
Questions that the labels could not decide (a name shared by two records, a phrase
that occurs in two CVE descriptions) are skipped.  Each case is assigned to the
``dev`` split (used to choose settings) or the ``test`` split (used only to report
the final figures).

    python -m backend.experiments.make_dataset      # writes backend/data/heldout_dataset.json
"""
from __future__ import annotations

import json
import random
import sys
from collections import Counter
from datetime import datetime, timezone

from backend.config import DATA_DIR, load_settings
from backend.database import Neo4jDatabase
from backend.evaluation import DATASET_PATH, load_dataset

FINAL_PATH = DATA_DIR / "heldout_dataset.json"      # reported on, never tuned on
TUNING_PATH = DATA_DIR / "tuning_dataset.json"      # used to choose settings
FINAL_SEED, TUNING_SEED = 20261115, 424242
OFF_DOMAIN = [
    "What is the capital of Australia?", "How do I bake sourdough bread?", "Who won the football world cup in 2010?",
    "Write a poem about the ocean", "What is the boiling point of water at sea level?",
    "Recommend a good science fiction novel", "How many planets are in the solar system?",
    "Translate 'good morning' into French", "What is the square root of 1764?", "How do I train a puppy to sit?",
    "Who painted the Mona Lisa?", "Explain how photosynthesis works", "What are the symptoms of the common cold?",
    "Plan a three day trip to Rome", "What is the tallest mountain in the world?", "Give me a workout routine for beginners",
    "Who is the author of Pride and Prejudice?", "How does a refrigerator keep food cold?",
    "What is the exchange rate between euro and dollar?", "Suggest a name for my new cat",
    "How do airplanes stay in the air?", "What is the plot of Romeo and Juliet?", "How long should I boil an egg?",
    "Which team has won the most basketball championships?",
]
SYLLABLES = ["zor", "blat", "quux", "vex", "mor", "tal", "grim", "flo", "ny", "dax", "kri", "pel", "sun", "wob", "yar", "hex"]
STRIP = ".,;:()\"'"


def _unique(rows, key):
    counts = Counter((row[key] or "").strip().lower() for row in rows)
    return [row for row in rows if row[key] and counts[row[key].strip().lower()] == 1]


def build(db: Neo4jDatabase, seed: int, per_category: int, split: str, exclude: list) -> dict:
    """``exclude``: dataset files whose entities must not appear (keeps the sets independent)."""
    rng = random.Random(seed)
    PER_CATEGORY = per_category
    earlier = load_dataset(DATASET_PATH)["cases"] + [c for p in exclude for c in load_dataset(p)["cases"]]
    used = {c.get("primary_id") for c in earlier} | {i for c in earlier for i in c.get("required_ids") or []}
    cases: list[dict] = []

    def add(category, difficulty, question, expect="answer", primary=None, facts=()):
        case = {"id": "", "category": category, "difficulty": difficulty, "question": question, "expect": expect}
        if expect == "answer":
            if primary:
                case["primary_id"] = primary
                case["required_ids"] = [primary]
            case["required_facts"] = [list(f) for f in facts]
        cases.append(case)

    # ---- CWE / CAPEC / ATT&CK: asked by identifier, by name or by alternate name
    spec = {"CWE": ("Which weakness is called {}?", "Which CWE is also known as {}?"),
            "CAPEC": ("Which attack pattern is called {}?", "Which CAPEC is also known as {}?"),
            "ATTACK": ("Which ATT&CK technique is called {}?", "Which ATT&CK technique is also known as {}?")}
    for label, (by_name, by_alias) in spec.items():
        rows = db._read(f"MATCH (n:{label}) RETURN n.id AS id, n.name AS name, "
                        "coalesce(n.alternate_terms, []) AS alt")
        rows = [r for r in _unique(rows, "name") if r["id"] not in used and 3 <= len(r["name"]) <= 90]
        alias_owner = Counter(a.strip().lower() for r in rows for a in r["alt"])
        rng.shuffle(rows)
        for index, row in enumerate(rows[:PER_CATEGORY]):
            aliases = [a for a in row["alt"] if alias_owner[a.strip().lower()] == 1 and len(a) > 3]
            if index % 3 == 0:
                add(label, "direct", f"What is {row['id']}?", primary=row["id"], facts=[[row["name"]]])
            elif index % 3 == 1 and aliases:
                add(label, "described", by_alias.format(aliases[0]), primary=row["id"], facts=[[row["name"]]])
            else:
                add(label, "described", by_name.format(row["name"]), primary=row["id"], facts=[[row["name"]]])

    # ---- CVE: by identifier, or by a phrase taken from its description
    ids = [r["id"] for r in db._read("MATCH (n:CVE) WHERE n.base_score IS NOT NULL RETURN n.id AS id")]
    rng.shuffle(ids)
    made = 0
    for cve_id in ids:
        if made >= PER_CATEGORY:
            break
        if cve_id in used:
            continue
        node = db.get_node("CVE", cve_id)
        words = " ".join((node.get("description") or "").split()).split()
        if not 12 <= len(words) <= 60:
            continue
        if made % 2 == 0:
            add("CVE", "direct", f"What is {cve_id}?", primary=cve_id, facts=[[str(node["base_score"])]])
        else:
            start = len(words) // 3
            phrase = " ".join(w.strip(STRIP) for w in words[start:start + 7])
            if not phrase.isascii() or db.cve_text_search([[phrase]], k=2)["total"] != 1:
                continue
            add("CVE", "described", f'Which vulnerability is described as "{phrase}"?', primary=cve_id)
        made += 1

    # ---- fundamentals
    terms = _unique(db._read("MATCH (n:CyberTerm) RETURN n.term AS term"), "term")
    terms = [t for t in terms if 3 <= len(t["term"]) <= 30 and t["term"].isascii()]
    rng.shuffle(terms)
    for row in terms[:16]:
        add("FUNDAMENTALS", "direct", f"What is {row['term']}?", facts=[[row["term"]]])

    # ---- harder: the entity is described by its own definition, without its name
    noun = {"CWE": "weakness", "CAPEC": "attack pattern", "ATTACK": "ATT&CK technique"}
    for label in ("CWE", "CAPEC", "ATTACK"):
        rows = db._read(f"MATCH (n:{label}) WHERE n.description IS NOT NULL "
                        "RETURN n.id AS id, n.name AS name, n.description AS d")
        rng.shuffle(rows)
        made = 0
        for row in rows:
            if made >= 12:
                break
            if row["id"] in used:
                continue
            sentence = " ".join(row["d"].split()).split(". ")[0].strip().rstrip(".")
            words = sentence.split()
            if not 8 <= len(words) <= 35 or not sentence.isascii() or (row["name"] or "").lower() in sentence.lower():
                continue
            same = db._read(f"MATCH (n:{label}) WHERE n.description STARTS WITH $p RETURN count(n) AS c", p=sentence[:50])
            if same[0]["c"] != 1:
                continue
            add(label, "described", f'Which {noun[label]} is described as: "{sentence}"?', primary=row["id"],
                facts=[[row["name"]]])
            made += 1

    # ---- harder: questions about the relationships stored in the graph
    def rel_cases(cypher, label, template, limit=8):
        rows = db._read(cypher)
        rng.shuffle(rows)
        made_here = 0
        for row in rows:
            if made_here >= limit or row["id"] in used:
                continue
            cases.append({"id": "", "category": label, "difficulty": "relationship",
                          "question": template.format(row["id"]), "expect": "answer", "primary_id": row["id"],
                          "required_ids": [row["id"]] + list(row["rel"]), "required_facts": []})
            made_here += 1

    rel_cases("MATCH (w:CWE)-[:CWE_CAPEC]->(c:CAPEC) WITH w, collect(DISTINCT c.id) AS rel "
              "WHERE size(rel) >= 1 AND size(rel) <= 4 RETURN w.id AS id, rel",
              "CWE", "Which attack patterns are related to {}?")
    rel_cases("MATCH (c:CAPEC)-[:CAPEC_ATTACK]->(t:ATTACK) WITH c, collect(DISTINCT t.id) AS rel "
              "WHERE size(rel) >= 1 AND size(rel) <= 4 RETURN c.id AS id, rel",
              "CAPEC", "Which ATT&CK techniques are mapped to {}?")
    taken = {c["primary_id"] for c in cases if c.get("primary_id")}
    made_here = 0
    for cve_id in ids:
        if made_here >= 8:
            break
        if cve_id in used or cve_id in taken:
            continue
        rel = [r["w"] for r in db._read("MATCH (:CVE {id:$i})-[:CVE_CWE]->(w:CWE) RETURN w.id AS w", i=cve_id)]
        if 1 <= len(rel) <= 3:
            cases.append({"id": "", "category": "CVE", "difficulty": "relationship",
                          "question": f"Which weakness is associated with {cve_id}?", "expect": "answer",
                          "primary_id": cve_id, "required_ids": [cve_id] + rel, "required_facts": []})
            made_here += 1

    # ---- things that do not exist: the correct output is RESULT NOT FOUND
    def absent_id(label, make):
        while True:
            candidate = make()
            if db.get_node(label, candidate) is None:
                return candidate

    for label, make, template in (
            ("CVE", lambda: f"CVE-{rng.randint(2040, 2099)}-{rng.randint(10000, 99999)}", "What is {}?"),
            ("CWE", lambda: f"CWE-{rng.randint(5000, 9999)}", "Explain {}"),
            ("CAPEC", lambda: f"CAPEC-{rng.randint(2000, 9999)}", "Describe {}"),
            ("ATTACK", lambda: f"T{rng.randint(7000, 9999)}", "What is {}?")):
        for _ in range(3):
            add(label, "direct", template.format(absent_id(label, make)), expect="not_found")
    templates = [("CWE", "Which weakness is called {}?"), ("CAPEC", "Which attack pattern is called {}?"),
                 ("ATTACK", "Which ATT&CK technique is called {}?"),
                 ("CVE", "Which vulnerability affects the {} firmware?")]
    for index in range(12):
        label, template = templates[index % 4]
        name = " ".join("".join(rng.choice(SYLLABLES) for _ in range(2)) for _ in range(2))
        if label != "CVE" or db.cve_text_search([[name.split()[0]]], k=1)["total"] == 0:
            add(label, "described", template.format(name), expect="not_found")
    for question in rng.sample(OFF_DOMAIN, 12):
        add("UNSUPPORTED", "described", question, expect="not_found")

    # ---- ids and the dev / test split (alternating inside every category)
    seen: Counter = Counter()
    for case in cases:
        key = (case["category"], case["expect"])
        case["id"] = f"h-{case['category'].lower()}-{case['expect'][:1]}{seen[key] + 1:02d}"
        case["split"] = split
        seen[key] += 1
    return {"version": "1.1", "seed": seed,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "graph": db.counts()["nodes"],
            "description": (f"Set generated from the knowledge graph with seed {seed} (split: {split}). Labels come "
                            "from the graph records, never from the assistant. The tuning set is used to choose "
                            "settings; the held-out set is only used to report the final figures."),
            "cases": cases}


def main() -> int:
    db = Neo4jDatabase(load_settings())
    try:
        final = build(db, FINAL_SEED, 40, "test", [])
        FINAL_PATH.write_text(json.dumps(final, indent=1, ensure_ascii=False), encoding="utf-8")
        tuning = build(db, TUNING_SEED, 64, "dev", [FINAL_PATH])
        TUNING_PATH.write_text(json.dumps(tuning, indent=1, ensure_ascii=False), encoding="utf-8")
    finally:
        db.close()
    for path, data in ((FINAL_PATH, final), (TUNING_PATH, tuning)):
        by = Counter((c["category"], c["difficulty"], c["expect"]) for c in data["cases"])
        print(len(data["cases"]), "cases ->", path.name, dict(Counter(c["difficulty"] for c in data["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
