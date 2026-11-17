# Running CyberIntelliX without your laptop

This guide moves the three parts that run on the laptop to free cloud services.
The frontend stays on Vercel.

| Part | Now (laptop) | After |
|---|---|---|
| Database | Neo4j on `localhost` | Neo4j AuraDB Free |
| Backend | `uvicorn` on port 8000 | Render free web service |
| Model | Ollama `llama3.2` | `openai/gpt-oss-120b` through the Groq API |
| Embeddings | `all-MiniLM-L6-v2` (ONNX Runtime) | the same model on Render, downloaded during the build |
| Public address | Temporary Cloudflare tunnel | Permanent `onrender.com` address |

Everything is done with settings, the `render.yaml` file in this folder and the
`copy-to` command.

## What the free tiers cannot do

* **Not every CVE.** AuraDB Free holds 200,000 nodes, 400,000 relationships and 1 GB
  (Neo4j's docs; its product page says 50,000 nodes, so check the limit shown in your
  Aura console). NVD holds over 420,000 CVEs and publishes about 100,000 a year, so
  `MAX_CVES=100000` keeps only the newest 100,000 (back to early January 2026 as of
  November 2026). Each update deletes the oldest CVEs beyond the cap and skips old CVEs
  that NVD modifies, so the database stays the same size. CWE, CAPEC, ATT&CK and the
  reference documents (about 2,900 nodes) are always kept in full. If the console shows
  50,000 nodes, use `MAX_CVES=45000`.
* **The backend sleeps.** Render stops a free service after 15 minutes without visitors.
  The next visit wakes it, which takes about a minute, and the page may show
  "backend offline" until then. Updates run only while it is awake; each wake-up catches up.
* **The database pauses.** Aura pauses a free database after a few days without use. Resume
  it from the Aura console.
* **Memory is tight.** Render gives 512 MB. The backend with the sentence-transformer
  embedding model (run with ONNX Runtime) uses about 280 MB (measured on the laptop).
  Reading a new ATT&CK release needs about 340 MB more, so that update will likely fail
  on Render. This happens only when MITRE publishes a release, a few times a year. When
  it does, update the laptop database and copy again (step 3).

## Step 1. Create the database (Neo4j Aura)

1. Sign up at <https://console.neo4j.io> and create a **Free** instance.
2. Download the credentials file it offers. It is shown only once. It contains
   `NEO4J_URI` (starts with `neo4j+s://`), `NEO4J_USERNAME` and `NEO4J_PASSWORD`.

## Step 2. Get a model key (Groq)

1. Sign up at <https://console.groq.com> and create an API key.
2. Keep the key for step 4. Check that the model named in `render.yaml`
   (`openai/gpt-oss-120b`) is still on Groq's model list; if not, pick another one
   from that list. Groq shut down its Llama chat models (`llama-3.3-70b-versatile`,
   `llama-3.1-8b-instant`) for free accounts on 16 August 2026.

## Step 3. Copy the data from the laptop (once)

The laptop database already holds everything, embeddings included, so it is copied
instead of downloaded and embedded again.

1. Save the Aura credentials file from step 1 in the project folder. `.gitignore`
   keeps files named `Neo4j-*.txt` or `aura*.txt` out of GitHub; do not rename it to
   anything else.
2. With the local Neo4j running, run:

   ```bash
   .venv\Scripts\python -m backend.manage copy-to Neo4j-xxxxxxxx-Created-....txt --max-cves 100000
   ```

   It copies CWE, CAPEC, ATT&CK, the reference documents and the newest 100,000 CVEs,
   rebuilds the relationships on Aura and copies the sync checkpoints, so the cloud
   backend continues with small incremental updates. It prints the counts in Aura at
   the end. It can be re-run safely.

The reference PDFs are not in the GitHub repository, so the cloud backend never re-reads
them. To change them, update the laptop database and copy again.

## Step 4. Start the backend (Render)

1. Push this project to GitHub so that `render.yaml` is in the repository.
2. Sign up at <https://render.com> with your GitHub account.
3. Choose **New > Blueprint**, pick the `RAG-Cyber` repository and confirm.
4. Render asks for four values: `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD` (step 1)
   and `LLM_API_KEY` (step 2).
5. When the deploy finishes, note the address, for example
   `https://cyberintellix-api.onrender.com`, and open `<address>/api/status`. It should
   say `"status":"ok"` and `"database_connected":true`.

## Step 5. Point the website at it (Vercel)

In the `vercel.json` of the deployed site, replace the tunnel address with the Render
address and redeploy:

```json
{
  "cleanUrls": true,
  "rewrites": [
    { "source": "/api/:path*", "destination": "https://cyberintellix-api.onrender.com/api/:path*" }
  ]
}
```

After this the laptop, Ollama, the local Neo4j and the Cloudflare tunnel are no longer
needed for the website.

## Keeping it awake (optional)

A free uptime monitor such as UptimeRobot can request `<address>/api/status` every
10 minutes. That stops the backend from sleeping, so the 2-hour and 24-hour updates run on
time. Render's free plan includes 750 hours a month, enough for one service running
all month.
