"""Build the Hugging Face Space folder (dist/hf-space) from this repository.

    python deploy/hf-space/build.py

The Space gets the backend, the website and a Dockerfile that adds the hosted
settings (Aura, Groq, MAX_CVES) to the project Dockerfile. Secrets are NOT in it:
they are entered in the Space's Settings > Variables and secrets.
"""
from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
OUT = ROOT / "dist" / "hf-space"

SKIP_DIRS = {"__pycache__", "tests", "logs", ".pytest_cache"}
SKIP_FILES = {".env"}

# Non-secret settings for the hosted backend (the same as render.yaml).
HOSTED_ENV = {
    "LLM_PROVIDER": "openai",
    "LLM_BASE_URL": "https://api.groq.com/openai/v1",
    "LLM_MODEL": "openai/gpt-oss-120b",
    "MAX_CVES": "150000",
    "NVD_SYNC_START_DATE": "2025-01-01",
    "UPDATE_INTERVAL_HOURS": "24",
    "NVD_UPDATE_INTERVAL_HOURS": "2",
    "SCHEDULER_ENABLED": "true",
    "RUN_INITIAL_SYNC": "true",
    "CORS_ORIGINS": "https://cyberintellix.vercel.app",
    "LOG_LEVEL": "INFO",
}


def copy_tree(src: Path, dst: Path) -> int:
    count = 0
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        if any(part in SKIP_DIRS for part in rel.parts) or path.name in SKIP_FILES:
            continue
        if rel.parts[:2] == ("data", "experiments") or rel.parts[:2] == ("data", "reference_docs"):
            continue  # results of past experiments; the documents are already in Aura
        if path.suffix == ".pyc":
            continue
        target = dst / rel
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            count += 1
    return count


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    files = copy_tree(ROOT / "backend", OUT / "backend")
    files += copy_tree(ROOT / "frontend", OUT / "frontend")
    (OUT / "backend" / "data" / "reference_docs").mkdir(parents=True, exist_ok=True)
    (OUT / "backend" / "data" / "reference_docs" / ".keep").write_text("", encoding="utf-8")

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    env_block = "\n# Hosted settings for the Hugging Face Space (no secrets here)\nENV " + " \\\n    ".join(
        f"{key}={value}" for key, value in HOSTED_ENV.items()) + "\n"
    marker = "EXPOSE 8000"
    if marker not in dockerfile:
        raise SystemExit("Dockerfile layout changed: 'EXPOSE 8000' not found")
    dockerfile = dockerfile.replace(marker, env_block.strip() + "\n\n" + marker)
    (OUT / "Dockerfile").write_text(dockerfile, encoding="utf-8", newline="\n")
    shutil.copy2(ROOT / ".dockerignore", OUT / ".dockerignore")
    shutil.copy2(HERE / "README.md", OUT / "README.md")
    print(f"{OUT}: {files + 3} files")


if __name__ == "__main__":
    main()
