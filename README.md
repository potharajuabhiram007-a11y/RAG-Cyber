# CyberIntelliX: Graph-RAG Cybersecurity Assistant

**Live app:** https://cyberintellix.vercel.app

| Part | Where it runs |
|---|---|
| Website | Vercel (`frontend/`) |
| Backend | Render free web service (`render.yaml`); it sleeps when idle, so the first question after a pause can take about a minute |
| Knowledge graph | Neo4j AuraDB Free |
| Language model | `openai/gpt-oss-120b` through the Groq API (locally: Ollama `llama3.2`, or none) |
| Embeddings | `BAAI/bge-small-en-v1.5` (384 dimensions) on the CPU with ONNX Runtime |

A Graph-RAG cybersecurity assistant that follows the GraphCyRAG methodology of
*Retrieval Augmented Generation for Robust Cyber Defense* (PNNL-36792). A curated Neo4j
knowledge graph holds **CVE, CWE, CAPEC and MITRE ATT&CK** records with their official
relationships, plus products, vendors, tactics and mitigations, and is kept up to date from
NVD and MITRE. A separate **cybersecurity and networking fundamentals** collection is built
from approved reference documents.

## What it does

* **Retrieval in a fixed order.** The graph first (identifiers, record names, glossary terms,
  words of CVE descriptions and the relationships of what was found). Only when the graph has
  no answer, semantic search over the embeddings. Only then other sources: loosely matching
  text, CVEs read live from the NVD, and finally the language model's own knowledge.
* **Spelling tolerance.** "waht is sql injectin" or "CEV 2021 44228" are corrected before
  retrieval; every correction is shown with the answer ("Interpreted: injectin → injection").
* **Confidence score.** Every answer carries a calibrated confidence (high / medium / low).
* **Grounded answers.** With an LLM configured, the model combines the evidence with its own
  knowledge and says which is which. A cybersecurity question the graph has nothing on is
  answered from general knowledge and labelled "General knowledge (not verified in the
  knowledge graph)". Identifiers the model mentions are checked against the graph; any that
  are not there are listed under "Not verified". With `LLM_PROVIDER=none` the answer is
  assembled only from retrieved evidence. Questions outside cybersecurity and networking
  return `RESULT NOT FOUND`.
* **Relationship graph** under each answer. Clicking a node opens its details in a side panel.
* **Automatic updates.** CVEs every 24 hours, CWE / CAPEC / ATT&CK about every 3 months.

## Project layout

```
RAG-Cyber/
├── backend/
│   ├── main.py              FastAPI app and REST endpoints
│   ├── api_extra.py         extra endpoints: statistics, kill chain, CVE filters, CVSS calculator
│   ├── database.py          Neo4j driver, schema, batch upserts, traversal, vector search
│   ├── curation.py          which records the graph keeps; node and relationship limits
│   ├── rebuild_graph.py     wipe and rebuild the graph from an export (plan / embed / load)
│   ├── config.py            environment-based configuration
│   ├── models.py            request / response models
│   ├── evaluation.py        offline benchmark (precision, recall, F1, accuracy)
│   ├── manage.py            command-line tasks (check, sync, ingest, evaluate, ask, reembed, copy-to)
│   ├── updater/
│   │   ├── cve_updater.py     NVD CVE API 2.0 (full + incremental, checkpoints)
│   │   ├── cwe_updater.py     MITRE CWE XML
│   │   ├── capec_updater.py   MITRE CAPEC XML
│   │   ├── attack_updater.py  MITRE ATT&CK STIX 2.1
│   │   ├── data_processor.py  HTTP retry, XML/STIX/PDF processing, embeddings, ingestion
│   │   ├── st_onnx.py         sentence-transformer embeddings with ONNX Runtime (no PyTorch)
│   │   └── scheduler.py       automatic background synchronisation
│   ├── rag/
│   │   ├── retriever.py       classification and the graph → semantic → other retrieval order
│   │   ├── spelling.py        spelling correction of questions
│   │   ├── confidence.py      confidence score of an answer
│   │   ├── external.py        live NVD lookup for CVEs the graph does not hold
│   │   ├── tuning.py          retrieval and generation settings
│   │   └── generator.py       grounded answers, hints, LLM providers
│   ├── experiments/           datasets, tuning sweeps, confidence calibration
│   ├── data/
│   │   ├── reference_docs/          approved foundational documents (PDF / .md / .txt)
│   │   ├── evaluation_dataset.json  labelled benchmark questions
│   │   └── experiments/             saved experiment runs and reports
│   ├── tests/                 automated tests (mocked NVD / MITRE, in-memory graph)
│   └── requirements.txt
├── frontend/                  index.html, style.css, script.js, fx.js (animations), hero3d.js (3D hero)
├── Dockerfile, docker-compose.yml
├── render.yaml                Render blueprint for the backend
├── DEPLOY.md                  moving the backend to Render, AuraDB and Groq
├── .env.example
└── README.md
```

## 1. Python environment setup

Python 3.11 or later is required. Run every command from the `RAG-Cyber` folder.

```bash
python -m venv .venv
```

Activate it: `.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (macOS/Linux).

## 2. Neo4j installation or Neo4j Aura configuration

Neo4j **5.11 or later** is needed (vector indexes). Choose one:

* **Neo4j Desktop / Community** - install from <https://neo4j.com/download/>, create a
  database, set a password and start it. The connection URI is `bolt://localhost:7687`,
  the user is `neo4j`.
* **Docker** - `docker run -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/<password> neo4j:5`
* **Neo4j Aura** - create an instance at <https://console.neo4j.io>, download the
  credentials file and use its `neo4j+s://...` URI, username, password and database name.
  Aura *Free* allows 200,000 nodes and 400,000 relationships; the curated graph (below)
  is built to stay under both. Fill a local graph first and copy it with
  `python -m backend.manage copy-to <credentials-file>`, see [DEPLOY.md](DEPLOY.md).

## 3. Creating and configuring `.env`

```bash
copy .env.example .env        # Windows   (cp .env.example .env on macOS/Linux)
```

Edit `.env`. Only the Neo4j settings are mandatory:

| Variable | Purpose |
|---|---|
| `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`, `NEO4J_DATABASE` | Neo4j connection (required) |
| `NVD_API_KEY` | optional free key; raises the NVD rate limit from 5 to 50 requests / 30 s |
| `NVD_SYNC_START_DATE` | optional; limit the first load to CVEs published since this date |
| `MAX_CVES` | keep only the newest N CVEs, deleting older ones as new ones arrive (150,000 on the live app; 0 = keep all) |
| `NVD_LIVE_LOOKUP` | allow the last retrieval step to read CVEs the graph does not hold live from the NVD (default `true`; only the CVE id or the product words are sent, never the question) |
| `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL`, `LLM_BASE_URL` | `none`, `anthropic`, `openai` (any OpenAI-compatible API, e.g. Groq or LM Studio) or `ollama` |
| `LLM_MAX_TOKENS` | output cap for hosted models (default 2048). A cut-off answer is trimmed to its last complete sentence |
| `LLM_EVIDENCE_CHARS` | evidence characters sent to a hosted model (default 9000). On HTTP 413 / 429 the request is retried once with half the evidence |
| `EMBEDDING_PROVIDER`, `EMBEDDING_MODEL`, `EMBEDDING_API_KEY`, `EMBEDDING_BASE_URL` | `sentence-transformers` (default, `BAAI/bge-small-en-v1.5`), `local` (feature hashing), `openai` or `ollama` |
| `EMBEDDING_RUNTIME` | `onnx` (default, about 280 MB in total) or `torch` |
| `EMBED_CVES` | also embed CVE descriptions (default `true`) |
| `UPDATE_INTERVAL_HOURS`, `NVD_UPDATE_INTERVAL_HOURS` | how often CWE, CAPEC and ATT&CK (default 2160 h, about 3 months) and CVE / NVD (default 24 h) are refreshed |
| `SCHEDULER_ENABLED`, `RUN_INITIAL_SYNC` | background updates on / off; catch up on missed updates at start-up |
| `ADMIN_API_KEY` | required for the manual sync endpoint |
| `CORS_ORIGINS` | addresses allowed to call the API (the Vercel address on the live app) |
| `TUNING_CONFIG` | optional path of a `tuned_config*.json` file |
| `LOG_LEVEL` | `INFO`, `DEBUG`, ... |

**Local development without any API key:** leave `LLM_PROVIDER=none`. Answers are
then assembled deterministically from the retrieved evidence (the UI labels them
"Extractive answer"). The embedding model needs no key; it is downloaded (about 90 MB)
from Hugging Face on first use. After changing the embedding provider or model run
`python -m backend.manage reembed`.

Secrets live only in `.env` (or in the host's environment settings); nothing is sent to
the browser and nothing needs to be edited in source code. If a required value is missing
the server stops with a one-line explanation.

## 4. Installing dependencies

```bash
pip install -r backend/requirements.txt
```

The embedding model runs with ONNX Runtime, so PyTorch is not needed. To use the
sentence-transformers library instead (same vectors, about twice the memory), install
`torch` (CPU build) and `sentence-transformers` and set `EMBEDDING_RUNTIME=torch`.

Check the configuration and the database connection:

```bash
python -m backend.manage check
```

## 5. Initial data synchronisation

Starting the server (step 6) synchronises everything automatically in the
background. To run it explicitly, or to watch the progress in the terminal:

```bash
python -m backend.manage sync foundation
```

```bash
python -m backend.manage sync mitre
```

```bash
python -m backend.manage sync nvd
```

* `foundation` indexes the documents in `backend/data/reference_docs/`.
* `mitre` downloads the official CWE XML, CAPEC XML and ATT&CK STIX data (about a minute).
* `nvd` loads CVEs through the NVD API 2.0. The full catalogue takes roughly 20-30 minutes
  with an API key and 2-3 hours without one. It is resumable: run the command again and it
  continues where it stopped. Later runs are incremental and take seconds.

Add `--full` to ignore checkpoints and reload a source. To build the curated graph from
an export of these records, see [Curated graph](#curated-graph) below.

## 6. Starting the backend

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

| Endpoint | Description |
|---|---|
| `POST /api/chat` | `{"message": "Explain CVE-2021-34527"}` -> answer, category, sources, related entities, relationships, confidence, spelling corrections, hint |
| `POST /api/chat/stream` | the same answer as newline-delimited JSON: `{"type":"delta","text":...}` while the model writes, then one `{"type":"final","response":{...}}`. The website uses this |
| `GET /api/status` | health and non-secret configuration |
| `GET /api/database/status` | Neo4j version, node and relationship counts |
| `GET /api/sync/status` | per-source status, last success, checkpoint, errors, next run |
| `POST /api/admin/sync` | manual sync; header `X-Admin-Key: <ADMIN_API_KEY>`, body `{"sources": ["all"], "full": false}` |
| `GET /api/metrics` | offline benchmark results |
| `GET /api/graph/search?q=` | find entities by identifier prefix or name |
| `GET /api/graph/entity/{id}` | one entity's details and a bounded sample of its neighbours |
| `GET /api/graph/overview` | the best-connected CWE / CAPEC / ATT&CK entities |
| `GET /api/graph/kill-chain/{id}`, `/api/graph/neighborhood/{id}` | multi-hop chain CVE → CWE → CAPEC → ATT&CK, and an entity's neighbourhood |
| `GET /api/cve/filter`, `/api/entities/search` | CVEs filtered by severity, year, minimum CVSS score or vendor / product; entity search |
| `GET /api/severity/cve/{id}`, `POST /api/severity/calculate` | CVSS score of a CVE; CVSS v3.1 calculator |
| `GET /api/stats/entities`, `/api/stats/relationships` | counts per label and relationship type |

Interactive API documentation: <http://127.0.0.1:8000/docs>.

**With Docker:** `docker compose up -d --build` starts Neo4j and the backend (with the
website) together, using the settings in `.env`; open <http://localhost:8000>.

## 7. The website

The backend serves the website: open <http://127.0.0.1:8000>. To host it separately (as on
Vercel), set `<meta name="rag-cyber-api" content="https://your-api-host">` in
`frontend/index.html` and add the website's address to `CORS_ORIGINS`.

The design is a blue glass theme with dark and light modes. The home page has a 3D hero
built with Three.js (`frontend/hero3d.js`): a glass shield with bloom and light rays.
Animations are in `frontend/fx.js`. There are five views:

- **Home** - ask a question. Answers stream in as they are written and show the confidence,
  any spelling corrections, the sources and a relationship graph; click a node for its
  details. One chat holds several questions. The Home link always returns to the home page,
  with "Back to your chat" to return; "New chat" starts again.
- **Features** - what the system does.
- **Resources** - links to the official sources, record and relationship counts and the
  state of each data source.
- **Knowledge Graph** - search for a CVE, CWE, CAPEC or ATT&CK record, expand its
  neighbours and read its details in the side panel.
- **History** - every question asked in this browser (stored in `localStorage`), searchable
  and filterable, with the full answer. Entries can be asked again or deleted.

## 8. Testing the chat assistant

Try these on the website (or with `python -m backend.manage ask "..."`):

| Message | Expected behaviour |
|---|---|
| `What is CVE-2021-44228?` | CVE details, linked CWE / CAPEC / ATT&CK, affected products, hint |
| `What is CWE-89 and which CAPEC patterns are related to it?` | CWE description, `CWE_CAPEC` traversal |
| `SQL injectin` / `waht is cros site scripting` | spelling corrected and shown; the named CWE, CAPEC and ATT&CK records |
| `Explain CAPEC-66` / `What is T1059 in MITRE ATT&CK?` | entity details and relationships |
| `buffer overflow in Apache Tomcat` | no identifier: CVE descriptions are searched and the closest records listed |
| `Which CVEs are linked to CWE-79?` | reverse traversal back to CVEs |
| `Explain the OSI model` / `What is TCP?` | fundamentals answer with its sources |
| `Hi, how are you?` | friendly greeting |
| `What is the capital of France?` | `RESULT NOT FOUND` |

Relationships that are not in the graph are reported as *not found*; they are never guessed.

### Measured results

Labelled questions from `backend/experiments/` (labels come from the graph records, never
from the assistant), each asked once correctly spelled and once with spelling mistakes.
Results in `backend/data/experiments/curated_graph_report.json`.

| Set | Questions | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|---|
| Tuning, correct spelling | 299 | 98.9% | 99.2% | 99.0% | 98.3% |
| Tuning, misspelled | 299 | 97.6% | 96.1% | 96.9% | 94.7% |
| Held-out, correct spelling | 226 | 97.9% | 99.5% | 98.7% | 97.8% |
| Held-out, misspelled | 226 | 97.2% | 93.5% | 95.3% | 92.5% |

The held-out set was never used to choose settings. The confidence model was fitted on the
tuning set and checked on the held-out answers (Brier score 0.041).

```bash
python -m backend.experiments.make_dataset        # build the tuning and held-out sets
python -m backend.experiments.run baseline        # retrieval on both sets
python -m backend.experiments.calibrate           # fit and check the confidence model
python -m backend.manage evaluate                 # the 99-question benchmark (GET /api/metrics)
```

### Automated tests

```bash
python -m pytest
```

The tests use mocked NVD / MITRE responses and an in-memory graph, so they need neither
network access nor Neo4j. One test about glossary definitions needs the two reference PDFs
in `backend/data/reference_docs/`, which are not in the repository.

## 9. Automatic updates

Updates run inside the backend process (APScheduler) and never block requests:

* CVE (NVD) incremental updates every `NVD_UPDATE_INTERVAL_HOURS` (default 24), using
  `lastModStartDate` / `lastModEndDate` with a 15-minute overlap; new CVEs pass the same
  curation rules and the oldest are removed to stay under the limits;
* MITRE CWE, CAPEC and ATT&CK every `UPDATE_INTERVAL_HOURS` (default 2160, about every 3 months).

The schedule is based on each source's last completed run, stored in Neo4j, so restarts
(for example Render's free plan going to sleep) neither reset the clock nor trigger a full
refresh. Updates are sized for Render's 512 MB: embeddings in token-limited batches and NVD
pages of 200 records. A failed run leaves existing data untouched, is reported in
`/api/sync/status` and is retried after 6 hours. Set `SCHEDULER_ENABLED=false` and use
`python -m backend.manage sync all` from cron / Task Scheduler instead if you prefer.

### Adding reference documents

Copy approved PDF, Markdown or text files into `backend/data/reference_docs/` and run
`python -m backend.manage ingest`. Glossary tables, abbreviation tables, `**Term**: definition`
lines and section text are indexed with the document title and page number. The collection
contains the PNNL research paper, the *Cybersecurity & Computer Networks - Basic Terms
Handbook* and a one-entry NIST glossary supplement.

## Knowledge graph

Live graph (AuraDB Free): about 164,000 nodes and 368,000 relationships.

| Node | Count | | Relationship | Direction | Source of the edge |
|---|---|---|---|---|---|
| CVE | 150,000 | | `CVE_CWE` | `(CVE)->(CWE)` | NVD `weaknesses` |
| CWE | 1,015 | | `CWE_CHILD` | `(child CWE)->(parent CWE)` | CWE `ChildOf` |
| CAPEC | 556 | | `CWE_CAPEC` | `(CWE)->(CAPEC)` | CWE / CAPEC cross references |
| ATTACK | 706 | | `CAPEC_CHILD` | `(child CAPEC)->(parent CAPEC)` | CAPEC `ChildOf` |
| Product | 8,670 | | `CAN_PRECEDE` | `(earlier CAPEC)->(later CAPEC)` | CAPEC `CanPrecede` / `CanFollow` |
| Vendor | 2,761 | | `CAPEC_ATTACK` | `(CAPEC)->(ATTACK)` | CAPEC taxonomy mappings, ATT&CK `capec` references |
| CyberTerm | 286 | | `SUBTECHNIQUE_OF` | `(sub-technique)->(technique)` | ATT&CK `subtechnique-of` |
| CyberDocument | 36 | | `AFFECTS` | `(CVE)->(Product)` | NVD CPE configurations |
| Mitigation | 44 | | `MADE_BY` | `(Product)->(Vendor)` | CPE vendor |
| Tactic | 15 | | `HAS_TACTIC`, `MITIGATES` | `(ATTACK)->(Tactic)`, `(Mitigation)->(ATTACK)` | ATT&CK kill-chain phases and mitigations |

Edges are created only from official cross references, never from text similarity. Every
node has an embedding and each label its own vector index.

## Curated graph

* **Limits.** Under 200,000 nodes and 400,000 relationships at all times: `NODE_LIMIT` /
  `REL_LIMIT` in `backend/curation.py` are checked before every write.
* **What is kept.** `backend/curation.py` refuses rejected, disputed, unscored and
  CVSS-v2-only records, and records without a description, weakness, affected product,
  reference or date; then the newest 150,000 CVEs remain. 16 well-known CVEs (Log4Shell,
  PrintNightmare, ...) are always kept. `CURATE_GRAPH=false` turns the rules off for updates.
* **Products and vendors** with 5 or more CVEs are created by a rebuild; updates link new
  CVEs to existing ones.
* **Rebuild.** `python -m backend.rebuild_graph plan|embed|load <export-folder>` judges every
  exported record (report in `curation_report.json`), computes the vectors and reloads the
  local graph. `replace-remote` copies the local graph to Aura.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| The live app answers slowly at first | the Render backend was asleep; it wakes within about a minute |
| `RAG-Cyber configuration error: Missing required configuration: NEO4J_URI ...` | create `.env` from `.env.example` and fill in the Neo4j values |
| `Neo4j is not reachable ...` / "Database unavailable" | start Neo4j; check `NEO4J_URI` (`bolt://localhost:7687` locally, `neo4j+s://...` for Aura) |
| `Neo4j rejected the credentials` | wrong `NEO4J_USERNAME` / `NEO4J_PASSWORD` |
| `Vector index ... was built for N-dimensional embeddings` | the embedding model changed: run `python -m backend.manage reembed` |
| NVD sync is slow or shows HTTP 403/429 retries | rate limiting; add `NVD_API_KEY`. The sync retries with backoff and resumes |
| Every question returns `RESULT NOT FOUND` | the initial synchronisation has not finished: see `/api/sync/status` |
| Fundamentals questions return `RESULT NOT FOUND` | run `python -m backend.manage ingest`; the term must exist in a reference document |
| Answers are labelled "Extractive answer" | no LLM configured, the LLM failed, or it cited identifiers not in the evidence |
| A hosted-model answer is slow or shorter than usual | the Groq free plan's per-minute limit was reached; the answer is retried with less evidence |
| `POST /api/admin/sync` returns 503 / 401 | set `ADMIN_API_KEY` / send it in the `X-Admin-Key` header |
| Website shows "Backend offline" | start uvicorn; when hosting the website elsewhere check the `rag-cyber-api` meta tag and `CORS_ORIGINS` |

Logs are written to the console and to `backend/logs/rag_cyber.log` (API keys and
passwords are never logged).
