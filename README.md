# RAG-Cyber: AI-Powered Cybersecurity Assistant

**Live app:** https://cyberintellix.vercel.app
(the page is hosted on Vercel; answers come from a backend running on the author's own machine, so the live app may be offline when that machine is off)

A Graph-RAG cybersecurity assistant that follows the GraphCyRAG methodology of
*Retrieval Augmented Generation for Robust Cyber Defense* (PNNL-36792): a Neo4j
knowledge graph of **CVE, CWE, CAPEC and MITRE ATT&CK** with their official
relationships, automatically synchronised from NVD and MITRE, plus a separate
**cybersecurity and networking fundamentals** collection built from approved
reference documents.

How answers are produced depends on whether an LLM is configured:

- **`LLM_PROVIDER=none` (default):** answers are assembled **only from retrieved
  evidence**. Anything outside the supported categories, or without sufficient
  evidence, returns exactly `RESULT NOT FOUND`.
- **An LLM is configured:** the model combines the retrieved evidence with its
  own knowledge and says which is which. A cybersecurity question the graph has
  nothing on is answered from general knowledge and labelled "General knowledge
  (not verified in the knowledge graph)". Identifiers the model mentions are
  checked against the graph; any that are not there are listed under
  "Not verified" at the end of the answer. Questions outside cybersecurity and
  networking still return `RESULT NOT FOUND`.

```
RAG-Cyber/
├── backend/
│   ├── main.py              FastAPI app and REST endpoints
│   ├── database.py          Neo4j driver, schema, batch upserts, traversal, vector search
│   ├── config.py            environment-based configuration
│   ├── models.py            request / response models
│   ├── evaluation.py        offline benchmark (precision, recall, F1, accuracy)
│   ├── manage.py            command-line tasks (sync, ingest, evaluate, ask, ...)
│   ├── updater/
│   │   ├── cve_updater.py     NVD CVE API 2.0 (full + incremental, checkpoints)
│   │   ├── cwe_updater.py     MITRE CWE XML
│   │   ├── capec_updater.py   MITRE CAPEC XML
│   │   ├── attack_updater.py  MITRE ATT&CK STIX 2.1
│   │   ├── data_processor.py  HTTP retry, XML/STIX/PDF processing, embeddings, ingestion
│   │   └── scheduler.py       automatic background synchronisation
│   ├── rag/
│   │   ├── retriever.py       classification, graph traversal, vector retrieval, validation
│   │   └── generator.py       grounded answers, hints, LLM providers
│   ├── data/
│   │   ├── reference_docs/          approved foundational documents (PDF / .md / .txt)
│   │   └── evaluation_dataset.json  labelled benchmark questions
│   ├── tests/                 automated tests (mocked NVD / MITRE, in-memory graph)
│   └── requirements.txt
├── frontend/                  index.html, style.css, script.js
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

* **Neo4j Desktop / Community (recommended for the full dataset)** - install from
  <https://neo4j.com/download/>, create a database, set a password and start it.
  The connection URI is `bolt://localhost:7687`, the user is `neo4j`.
* **Docker** - `docker run -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/<password> neo4j:5`
* **Neo4j Aura** - create an instance at <https://console.neo4j.io>, download the
  credentials file and use its `neo4j+s://...` URI, username and password.
  Aura *Free* is limited to 200,000 nodes, which is less than the full NVD
  catalogue (300,000+ CVEs); set `NVD_SYNC_START_DATE` (for example `2023-01-01`)
  to load only recent CVEs.

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
| `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL`, `LLM_BASE_URL` | `none`, `anthropic`, `openai` (any OpenAI-compatible API, e.g. LM Studio) or `ollama` |
| `EMBEDDING_PROVIDER`, `EMBEDDING_API_KEY`, `EMBEDDING_MODEL`, `EMBEDDING_BASE_URL` | `local`, `openai` or `ollama` |
| `UPDATE_INTERVAL_HOURS`, `NVD_UPDATE_INTERVAL_HOURS` | schedule of MITRE and NVD updates |
| `ADMIN_API_KEY` | required for the manual sync endpoint |
| `LOG_LEVEL` | `INFO`, `DEBUG`, ... |

**Local development without any API key:** leave `LLM_PROVIDER=none` and
`EMBEDDING_PROVIDER=local`. Answers are then assembled deterministically from
the retrieved evidence (the UI labels them "Extractive answer") and embeddings
come from a built-in hashing embedder. For better wording configure an LLM; for
better semantic search configure a neural embedding model, then run
`python -m backend.manage reembed`.

Secrets live only in `.env`; nothing is sent to the browser and nothing needs to
be edited in source code. If a required value is missing the server stops with a
one-line explanation.

## 4. Installing dependencies

```bash
pip install -r backend/requirements.txt
```

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
* `nvd` loads CVEs through the NVD API 2.0. The **full catalogue takes roughly
  20-30 minutes with an API key and 2-3 hours without one** (rate limits). It is
  resumable: if it is interrupted, run the command again and it continues where
  it stopped. Later runs are incremental and take seconds.

Add `--full` to ignore checkpoints and reload a source.

## 6. Starting the backend

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

| Endpoint | Description |
|---|---|
| `POST /api/chat` | `{"message": "Explain CVE-2021-34527"}` -> answer, category, sources, related entities, relationships, metrics, hint |
| `GET /api/status` | health and non-secret configuration |
| `GET /api/database/status` | Neo4j version, node and relationship counts |
| `GET /api/sync/status` | per-source status, last success, checkpoint, errors, next run |
| `POST /api/admin/sync` | manual sync; header `X-Admin-Key: <ADMIN_API_KEY>`, body `{"sources": ["all"], "full": false}` |
| `GET /api/metrics` | offline benchmark results |
| `POST /api/chat/stream` | the same answer as `/api/chat`, as newline-delimited JSON: `{"type":"delta","text":...}` while the language model writes, then one `{"type":"final","response":{...}}`. The web page uses this so the answer appears as it is written |
| `GET /api/graph/search?q=` | find entities by identifier prefix or name (Knowledge Graph view) |
| `GET /api/graph/entity/{id}` | one entity's details and a bounded sample of its neighbours |
| `GET /api/graph/overview` | the best-connected CWE / CAPEC / ATT&CK entities |

Interactive API documentation: <http://127.0.0.1:8000/docs>.

## 7. Starting the frontend

The backend serves the frontend: open <http://127.0.0.1:8000>.

To host it separately (for example `python -m http.server 5500 --directory frontend`),
the page falls back to `http://127.0.0.1:8000` for the API automatically; for any
other address set `<meta name="rag-cyber-api" content="https://your-api-host">` in
`frontend/index.html` and add the frontend origin to `CORS_ORIGINS`.

The home hero draws three floating 3D panels (network, lock, fingerprint) with Three.js (`frontend/hero3d.js`, library vendored in `frontend/vendor/`, MIT licence). Browsers without WebGL fall back to the flat SVG artwork in `index.html`.

The interface is branded **CyberIntelliX** (black-and-lime glass design) and has five views, reached from the navigation at the top.
Home takes one question per chat; "New chat" returns to the start screen.

- **Home** - ask a question; each answer shows its relationship graph, sources and benchmark figures.
- **History** - every question asked in this browser (stored in `localStorage`, newest first), searchable
  and filterable, with the full answer on the right. Entries can be re-asked or deleted.
- **Knowledge Graph** - search for a CVE, CWE, CAPEC or ATT&CK record, select a node to load its
  neighbours, and read the entity's details in the panel on the right.
- **Features** - a summary of what the system does.
- **Resources** - links to the official sources, record and relationship counts and the state of each data source.

## 8. Testing the chat assistant

Try these in the browser (or with `python -m backend.manage ask "..."`):

| Message | Expected behaviour |
|---|---|
| `What is CVE-2021-34527?` | CVE details from NVD, linked CWE/CAPEC/ATT&CK where the graph has them, evidence-based hint |
| `What is CWE-89 and which CAPEC patterns are related to it?` | CWE description, `CWE_CAPEC` traversal |
| `Explain CAPEC-66` / `What is the meaning of T1059 in MITRE ATT&CK?` | entity details and relationships |
| `Explain the vulnerability that allows a remote attacker to cause a DoS in Windows NT` / `buffer overflow in Apache Tomcat` | no identifier given: the CVE descriptions are searched (full-text index `cve_descriptions`), the closest record is described in full and other matches are listed; `RESULT NOT FOUND` when no description contains all the terms |
| `Explain the OSI model` / `What is TCP?` | fundamentals answer with its sources |
| `Hi, how are you?` | friendly greeting |
| `What is the capital of France?` | `RESULT NOT FOUND` |

The metrics and "Recommended actions" sections appear only on CVE / CWE / CAPEC /
ATT&CK answers. For every other reply the API still returns null metrics and the
hint text `THERE IS NO SOLUTION FOR THIS QUESTION`; the web UI simply does not draw
empty sections for them.

Relationships that are not present in the graph are reported as *not found*; they
are never guessed. (Official data changes: for example NVD currently lists no
specific CWE for CVE-2021-34527, so the assistant says so.)

### Evaluation metrics (Precision, F1 Score, Accuracy)

The metrics panel shows `--` until you run the labelled benchmark on your own graph:

```bash
python -m backend.manage evaluate
```

This runs `backend/data/evaluation_dataset.json` through the complete assistant
and writes `backend/data/evaluation_results.json`. From then on, CVE / CWE /
CAPEC / ATT&CK answers show the benchmark values of their category. They are
**offline benchmark metrics**, not a correctness guarantee for an individual
answer; a per-answer precision or accuracy cannot be computed without ground
truth, so none is invented. The TP / FP / FN / TN definition is documented at
the top of `backend/evaluation.py`. The benchmark questions reference specific
CVEs, so run it after a full NVD sync (CVEs missing from your graph count as
false negatives).

The dataset (version 2.0, 99 cases) has two kinds of question. **Direct**
questions name an exact identifier ("What is CWE-89?"); these are close to a
plain lookup and score near 100%. **Described** questions name the entity only
by a nickname, a name or a description ("What is the Log4Shell vulnerability?",
"Which weakness covers path traversal?") or ask about something that does not
exist; these are where the system makes mistakes. Results are stored per
category and per difficulty (`by_difficulty` in the results file and in
`GET /api/metrics`). An answer only counts as correct when it is *about* the
expected entity (`primary_id`) and carries no "Not verified" note.

A stored benchmark is shown only while it still describes the running system.
After changing `LLM_PROVIDER`, `LLM_MODEL` or the dataset, the metrics show `--`
until you run the benchmark again. With a local LLM the run takes much longer,
because every case waits for the model.

### Tuning experiments (`backend/experiments/`)

The retrieval and generation settings live in one object, `backend/rag/tuning.py`
(`Tuning`); its defaults reproduce the behaviour before the experiments existed. The
experiment tools change one setting at a time, measure the result and save every run
(parameters, dataset hash, metrics, per-question outcomes) in `backend/data/experiments/`.

```bash
python -m backend.experiments.make_dataset        # two independent seeded sets, labels read from the graph
python -m backend.experiments.run baseline        # defaults on both sets (retrieval only)
python -m backend.experiments.run sweep           # one-factor-at-a-time retrieval grid on the tuning set
python -m backend.experiments.run sweep --llm --limit 60     # generation settings, fixed stratified sample
python -m backend.experiments.run select [--llm --limit 60]  # pick by the fixed rule, write tuned_config*.json
python -m backend.experiments.run report [--llm --limit 100] # original vs tuned on the held-out set
```

* `tuning_dataset.json` (seed 424242) is used to choose settings; `heldout_dataset.json`
  (seed 20261115) only to report the final figures. They share no entities with each other
  or with the 99-question benchmark. Labels come from the graph records, never from the
  assistant. Question types: exact ID, exact name, alternate name, a description with the
  name removed, relationships, things that do not exist, and off-topic questions.
* Metrics are the ones of `backend/evaluation.py` (precision, recall, F1, accuracy), plus
  Precision@K, Recall@K, MRR, groundedness (share of answer sentences supported by the
  retrieved evidence) and latency. Formulas and labels are never adjusted for a target.
* Selection rule (fixed in `run.py:score`): maximise F1 + accuracy on the tuning set; a
  change must beat the default by at least 0.005 to be kept.
* To run the application with a selected configuration set `TUNING_CONFIG` in `.env` to the
  path of the `tuned_config*.json` file. Benchmark results made with other parameters are
  treated as out of date by the metrics panel.

**Measured results (held-out set, never used for choosing settings; files in
`backend/data/experiments/`).** No setting beat the defaults on the tuning set, so the
selected configuration is the default and Original = Tuned:

| Metric | Original = Tuned (retrieval only, 272 q) | Original = Tuned (with Ollama llama3.2, 99-q stratified sample) |
|---|---|---|
| Precision | 98.3% | 95.3% |
| Recall | 98.7% | 98.8% |
| F1-score | 98.5% | 97.0% |
| Accuracy | 97.4% | 95.0% |
| MRR | 0.969 | 0.963 |
| Groundedness | 0.821 | 0.718 |

These are above 80-89%. Settings that land in that range exist only by degrading the
system (e.g. `entity_full_cov=1.0` gave recall 88.3%), and were not selected. Note: the
first, easier dataset (only ID/name questions) was replaced by harder graph-derived sets
after its baseline looked too easy; the replacement was decided from the baseline, not from
tuned results.

### Automated tests

```bash
python -m pytest
```

The tests use mocked NVD / MITRE responses and an in-memory graph, so they need
neither network access nor Neo4j.

## 9. Scheduling automatic updates

Updates run inside the backend process (APScheduler) and never block requests:

* MITRE CWE, CAPEC, ATT&CK and the reference documents every `UPDATE_INTERVAL_HOURS` (default 24);
* NVD incremental updates every `NVD_UPDATE_INTERVAL_HOURS` (default 2), using
  `lastModStartDate` / `lastModEndDate` with a 15-minute overlap.

A source is never synchronised twice at once, each source has its own checkpoint,
and a checkpoint only advances after the data has been written. A failed run
leaves existing data untouched, is reported in `/api/sync/status` and is retried
at the next interval. Set `SCHEDULER_ENABLED=false` to disable it and use
`python -m backend.manage sync all` from cron / Task Scheduler instead.

### Adding reference documents

Copy approved PDF, Markdown or text files into `backend/data/reference_docs/` and
run `python -m backend.manage ingest`. Glossary tables (`Term | Meaning`),
abbreviation tables, `**Term**: definition` lines and section text are indexed
with the document title and page number. The collection currently contains the
PNNL research paper, the *Cybersecurity & Computer Networks - Basic Terms
Handbook* and a one-entry NIST glossary supplement (definition of
"cybersecurity", quoted from csrc.nist.gov) - delete that file if you do not want it.

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `RAG-Cyber configuration error: Missing required configuration: NEO4J_URI ...` | create `.env` from `.env.example` and fill in the Neo4j values |
| `Neo4j is not reachable ...` / status pill "Database unavailable" | start Neo4j; check `NEO4J_URI` (`bolt://localhost:7687` locally, `neo4j+s://...` for Aura) |
| `Neo4j rejected the credentials` | wrong `NEO4J_USERNAME` / `NEO4J_PASSWORD` |
| `Vector index ... was built for N-dimensional embeddings` | the embedding model changed: run `python -m backend.manage reembed` |
| "Vector index could not be created" in the log | Neo4j older than 5.11; upgrade (ID, term and name lookups still work) |
| NVD sync is slow or shows HTTP 403/429 retries | rate limiting; add `NVD_API_KEY`. The sync retries with backoff and resumes |
| Every dataset question returns `RESULT NOT FOUND` | the initial synchronisation has not finished: see `/api/sync/status` |
| Fundamentals questions return `RESULT NOT FOUND` | run `python -m backend.manage ingest`; the term must exist in a reference document |
| Answers are labelled "Extractive answer" | no LLM configured, the LLM failed, or its answer cited identifiers that were not in the evidence |
| Metrics show `--` for CVE/CWE/CAPEC/ATT&CK | run `python -m backend.manage evaluate` |
| `POST /api/admin/sync` returns 503 / 401 | set `ADMIN_API_KEY` in `.env` / send it in the `X-Admin-Key` header |
| Browser shows "Backend offline" | start uvicorn; when hosting the frontend elsewhere check the `rag-cyber-api` meta tag and `CORS_ORIGINS` |

Logs are written to the console and to `backend/logs/rag_cyber.log` (API keys and
passwords are never logged).

## Knowledge graph

Nodes: `CVE`, `CWE`, `CAPEC`, `ATTACK`, `CyberTerm`, `CyberDocument` (unique `id`,
vector index on `embedding`).

| Relationship | Direction | Official source of the edge |
|---|---|---|
| `CVE_CWE` | `(CVE)->(CWE)` | NVD `weaknesses` |
| `CWE_CHILD` | `(child CWE)->(parent CWE)` | CWE `Related_Weakness Nature="ChildOf"` |
| `CWE_CAPEC` | `(CWE)->(CAPEC)` | CWE `Related_Attack_Patterns`, CAPEC `Related_Weaknesses` |
| `CAPEC_CHILD` | `(child CAPEC)->(parent CAPEC)` | CAPEC `ChildOf` |
| `CAN_PRECEDE` | `(earlier CAPEC)->(later CAPEC)` | CAPEC `CanPrecede` / `CanFollow` |
| `CAPEC_ATTACK` | `(CAPEC)->(ATTACK)` | CAPEC `Taxonomy_Mappings` (ATTACK), ATT&CK `capec` references |
| `SUBTECHNIQUE_OF` | `(sub-technique)->(technique)` | ATT&CK `subtechnique-of` relationships |

Edges are created only from these cross references, never from text similarity.
