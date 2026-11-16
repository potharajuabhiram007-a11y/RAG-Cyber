# Running CyberIntelliX without your laptop

This guide moves the three parts that run on the laptop to free cloud services.
The frontend stays on Vercel.

| Part | Now (laptop) | After |
|---|---|---|
| Database | Neo4j on `localhost` | Neo4j AuraDB Free |
| Backend | `uvicorn` on port 8000 | Render free web service |
| Model | Ollama `llama3.2` | Hosted llama model through the Groq API |
| Public address | Temporary Cloudflare tunnel | Permanent `onrender.com` address |

No application code changes are needed. Everything is done with settings, plus the
`render.yaml` file in this folder.

## What the free tiers cannot do

* **Not every CVE.** AuraDB Free holds 200,000 nodes. The full NVD catalogue is larger, so
  only CVEs published since `NVD_SYNC_START_DATE` are loaded. `2024-01-01` gives roughly
  135,000 CVEs today and leaves about a year of room for new ones. Use `2025-01-01` for
  more room and fewer CVEs.
* **The backend sleeps.** Render stops a free service after 15 minutes without visitors.
  The next visit wakes it, which takes about a minute, and the page may show
  "backend offline" until then. Updates run only while it is awake; each wake-up catches up.
* **The database pauses.** Aura pauses a free database after a few days without use. Resume
  it from the Aura console.
* **Memory is tight.** Render gives 512 MB. Reading a new ATT&CK release needs about
  340 MB on its own (measured on the laptop), so that update could fail on Render. This
  happens only when MITRE publishes a release, a few times a year. If it fails, run that
  update once from the laptop (step 3).

## Step 1. Create the database (Neo4j Aura)

1. Sign up at <https://console.neo4j.io> and create a **Free** instance.
2. Download the credentials file it offers. It is shown only once. It contains
   `NEO4J_URI` (starts with `neo4j+s://`), `NEO4J_USERNAME` and `NEO4J_PASSWORD`.

## Step 2. Get a model key (Groq)

1. Sign up at <https://console.groq.com> and create an API key.
2. Keep the key for step 4. Check that the model named in `render.yaml`
   (`llama-3.3-70b-versatile`) is still on Groq's model list; if not, pick another one
   from that list.

## Step 3. Load the data from the laptop (once)

The first load is long, so do it from the laptop where nothing goes to sleep.

1. In `.env`, set the three `NEO4J_...` values from step 1 and set
   `NVD_SYNC_START_DATE=2024-01-01`. Keep a copy of the old values if you still want the
   local database.
2. Start the backend as usual:

   ```bash
   .venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
   ```

3. Open <http://127.0.0.1:8000/api/sync/status> and wait until all five sources show
   `success`. Without an NVD API key expect this to take a good while.
4. Stop the backend. The data, including the reference PDFs, is now in Aura.

The reference PDFs are not in the GitHub repository, so the cloud backend never re-reads
them. To change them, repeat this step from the laptop.

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
