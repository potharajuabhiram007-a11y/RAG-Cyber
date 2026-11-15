"""Command-line entry for the tuning experiments.

    python -m backend.experiments.run baseline              # defaults, dev + test, no LLM
    python -m backend.experiments.run sweep                 # one-factor-at-a-time grid, dev split, no LLM
    python -m backend.experiments.run sweep --llm           # the generation settings, with the LLM
    python -m backend.experiments.run select [--llm]        # combine the winners, write tuned_config.json
    python -m backend.experiments.run report [--llm]        # original vs tuned on the held-out test split

The selection rule is fixed in ``score()``: maximise F1 + accuracy on the dev split,
ties broken by lower latency.  The test split is only read by ``report``.
"""
from __future__ import annotations

import argparse
import json
import sys

from backend.config import DATA_DIR, load_settings
from backend.database import Neo4jDatabase
from backend.experiments import harness
from backend.rag.tuning import DEFAULT_TUNING, Tuning
from backend.updater.data_processor import EmbeddingClient

TUNED_PATH = DATA_DIR / "tuned_config.json"
MIN_GAIN = 0.005          # a setting must beat the default by at least this much to be kept

RETRIEVAL_GRID = {
    "name_search_k": [4, 16],
    "vector_k": [3, 10],
    "vector_min_score": [0.45, 0.66, 0.75],
    "entity_full_cov": [0.5, 1.0],
    "fundamentals_coverage": [0.4, 0.8],
    "cve_pool_k": [10, 100],
    "cve_result_k": [3, 10],
    "extra_entries": [0, 6],
    "max_hops": [1, 2],
    "rank_weighted": [
        {"rank_mode": "weighted"},
        {"rank_mode": "weighted", "w_desc": 0.5},
        {"rank_mode": "weighted", "w_vector": 1.0},
        {"rank_mode": "weighted", "w_length": 0.05},
    ],
}
GENERATION_GRID = {
    "temperature": [0.0, 0.4],
    "brief_answers": [False],
    "verified_facts": [False],
    "flag_unverified": [False],
    "evidence_chars": [3000],
}


def score(record: dict) -> tuple:
    m = record["overall"]
    value = (m["f1_score"] or 0.0) + (m["accuracy"] or 0.0)
    return (round(value, 4), -record["latency_seconds"]["mean"])


def variants(grid: dict):
    for key, values in grid.items():
        for value in values:
            changes = value if isinstance(value, dict) else {key: value}
            label = "+".join(f"{k}={v}" for k, v in changes.items())
            yield f"{key}:{label}" if isinstance(value, dict) else label, changes


def context():
    settings = load_settings()
    return Neo4jDatabase(settings), EmbeddingClient(settings), settings


def progress(prefix):
    def show(done, total):
        if done == total or done % 30 == 0:
            print(f"    {prefix} {done}/{total}", flush=True)
    return show


def run(db, embedder, settings, name, tuning, split, use_llm, group="", limit=None):
    """split "dev" = the tuning set, "test" = the held-out set (final report only)."""
    path = harness.TUNING_PATH if split == "dev" else harness.HELDOUT_PATH
    print(f"  {name} [{path.stem}{', llm' if use_llm else ''}]", flush=True)
    record = harness.run_experiment(db, embedder, settings, name, tuning, "all", use_llm, dataset_path=path,
                                    group=group, progress=progress(name) if use_llm else None, limit=limit)
    print("   ", harness.headline(record), flush=True)
    return record


def load_records(split="dev", use_llm=False, limit=None):
    tag = "llm" if use_llm else "nollm"
    out = {}
    stem = "tuning" if split == "dev" else "heldout"
    for path in sorted(harness.EXPERIMENT_DIR.glob(f"*__{stem}-all{f'-n{limit}' if limit else ''}__{tag}.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        out[record["name"]] = record
    return out


def cmd_baseline(args):
    db, embedder, settings = context()
    try:
        for split in ("dev", "test"):
            run(db, embedder, settings, "default", DEFAULT_TUNING, split, args.llm, group="baseline")
    finally:
        db.close()


def cmd_sweep(args):
    db, embedder, settings = context()
    grid = GENERATION_GRID if args.llm else RETRIEVAL_GRID
    try:
        run(db, embedder, settings, "default", DEFAULT_TUNING, "dev", args.llm, group="baseline", limit=args.limit)
        for name, changes in variants(grid):
            run(db, embedder, settings, name, DEFAULT_TUNING.replace(**changes), "dev", args.llm, group="sweep",
                limit=args.limit)
    finally:
        db.close()


def cmd_select(args):
    """Keep every single change that clearly beat the default, test them together on dev,
    and keep whichever of {default, each winner, combination} scores best on dev."""
    records = load_records("dev", args.llm, args.limit)
    base = records.get("default")
    if base is None:
        sys.exit("Run the baseline / sweep on the dev split first.")
    winners = {}
    for name, record in records.items():
        if name == "default" or record["group"] != "sweep":
            continue
        gain = score(record)[0] - score(base)[0]
        if gain >= MIN_GAIN:
            for key in record["changed_from_default"]:
                if key not in winners or gain > winners[key][0]:
                    winners[key] = (gain, record["changed_from_default"][key], name)
    print("single changes that beat the default:", {k: (v[1], round(v[0], 4)) for k, v in winners.items()})
    db, embedder, settings = context()
    try:
        candidates = {"default": base}
        for name, record in records.items():
            if name != "default" and record["group"] == "sweep" and score(record)[0] - score(base)[0] >= MIN_GAIN:
                candidates[name] = record
        if winners:
            tuning = DEFAULT_TUNING.replace(**{k: v[1] for k, v in winners.items()})
            candidates["combined"] = run(db, embedder, settings, "combined", tuning, "dev", args.llm, group="combined", limit=args.limit)
    finally:
        db.close()
    best_name = max(candidates, key=lambda n: score(candidates[n]))
    best = candidates[best_name]
    payload = {"selected": best_name, "selected_on": "dev split", "selection_rule": "max(F1 + accuracy), ties: lower latency",
               "min_gain_over_default": MIN_GAIN, "llm": args.llm, "parameters": best["parameters"],
               "dev_metrics": {"overall": best["overall"], "retrieval": best["retrieval"],
                               "groundedness": best["groundedness"], "latency_seconds": best["latency_seconds"]},
               "default_dev_metrics": {"overall": base["overall"]},
               "candidates": {n: {"score": score(r)[0], "changed": r["changed_from_default"]} for n, r in candidates.items()}}
    path = TUNED_PATH.with_name("tuned_config_llm.json" if args.llm else "tuned_config.json")
    path.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    print("selected:", best_name, "->", path)


def table(original, tuned):
    rows = [("Precision", "precision"), ("Recall", "recall"), ("F1-score", "f1_score"), ("Accuracy", "accuracy")]
    pct = lambda v: "n/a" if v is None else f"{v * 100:.1f}%"
    lines = ["| Metric | Original | Tuned |", "|---|---|---|"]
    lines += [f"| {label} | {pct(original['overall'][key])} | {pct(tuned['overall'][key])} |" for label, key in rows]
    for label, key in (("MRR", "mrr"), ("Precision@1", "p@1"), ("Recall@5", "r@5")):
        lines.append(f"| {label} | {original['retrieval'][key]} | {tuned['retrieval'][key]} |")
    lines.append(f"| Groundedness | {original['groundedness']['sentence_support']} | {tuned['groundedness']['sentence_support']} |")
    lines.append(f"| Latency (s/question) | {original['latency_seconds']['mean']} | {tuned['latency_seconds']['mean']} |")
    return "\n".join(lines)


def cmd_report(args):
    path = TUNED_PATH.with_name("tuned_config_llm.json" if args.llm else "tuned_config.json")
    tuned = Tuning.from_file(path)
    db, embedder, settings = context()
    try:
        original = run(db, embedder, settings, "original", DEFAULT_TUNING, "test", args.llm, group="final",
                       limit=args.limit)
        final = run(db, embedder, settings, "tuned", tuned, "test", args.llm, group="final", limit=args.limit)
    finally:
        db.close()
    text = table(original, final)
    out = harness.EXPERIMENT_DIR / f"final_report_{'llm' if args.llm else 'nollm'}.md"
    out.write_text(f"Held-out test split ({original['dataset_cases']} questions), "
                   f"{'with the LLM' if args.llm else 'retrieval only (no LLM)'}\n\n{text}\n\n"
                   f"Tuned parameters changed from default: {final['changed_from_default']}\n", encoding="utf-8")
    print(text)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name, fn in (("baseline", cmd_baseline), ("sweep", cmd_sweep), ("select", cmd_select), ("report", cmd_report)):
        p = sub.add_parser(name)
        p.add_argument("--llm", action="store_true")
        p.add_argument("--limit", type=int, default=None, help="fixed stratified sample size (for slow LLM runs)")
        p.set_defaults(fn=fn)
    args = parser.parse_args(argv)
    args.fn(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
