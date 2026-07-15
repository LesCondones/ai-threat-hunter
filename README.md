# AI Threat Hunting & Triage Pipeline

An automated security pipeline that ingests real-world LLM jailbreak data, uses Claude — via a LangGraph agent with retrieval-augmented context and a persistent analyst-feedback memory — to triage threats against MITRE ATLAS, generates YARA detection rules, and produces actionable security reports.

Built as a demonstration of merging traditional threat intelligence workflows with AI-driven automation.

---

## What It Does

```
ingest → analyze (retrieve + procedural memory) → detect → report
```

with a separate analyst **feedback** loop closing back into procedural memory.

1. **Ingests** jailbreak prompt datasets from HuggingFace into a local SQLite database
2. **Triages** high-priority threats (score ≥ 80) with a LangGraph retrieve-analyze-validate-retry loop: Claude is grounded against retrieved MITRE ATLAS techniques and past analyst corrections, then its tactic mapping is validated against what was actually retrieved (re-querying up to 3 times on failure, or flagging `needs_review` on repeated failure)
3. **Extracts** intent, MITRE ATLAS technique mappings, IoCs, and severity ratings from each threat, and persists the episode (prompt + analysis) to an S3 Vectors index for future recall
4. **Generates** YARA detection rules automatically from extracted IoCs and uploads them to S3
5. **Produces** a structured Markdown threat intelligence report and uploads it to S3
6. **Analysts review** flagged records via a CLI; corrections are stored and surfaced as extra context the next time a similar prompt is triaged

One command runs the entire pipeline:

```bash
uv run main.py
```

---

## How It Maps to Real Security Work

| Security Task | How This Project Implements It |
|---|---|
| Threat ingestion & OSINT | Pulls from HuggingFace jailbreak datasets, stores in SQLite with deduplication |
| AI-assisted triage | Claude/LangGraph agent classifies intent and maps to MITRE ATLAS, grounded via RAG |
| Grounding / hallucination control | Validates the returned tactic against the techniques actually retrieved that turn; retries or flags for review otherwise |
| IoC extraction | Automatically extracts malicious strings, trigger phrases, persona keywords |
| Detection engineering | Generates YARA rules from extracted IoCs for each threat, stored in S3 |
| High-signal reporting | Produces structured Markdown reports with severity breakdown and ATLAS mappings, stored in S3 |
| Analyst feedback loop | CLI-driven review of flagged records; corrections feed back into future triage via procedural memory |
| Episodic/procedural memory | Past analyzed prompts and analyst corrections are embedded and recalled for similar future prompts |
| Automation | Full pipeline runs end-to-end without human intervention |

---

## Project Structure

```
ai-triage-agent/
├── main.py               ← entry point — runs full pipeline
├── ingestion/             ← pulls raw data in (HuggingFace jailbreaks, MITRE ATLAS catalog)
│   ├── ingest.py            ← fetches jailbreak data from HuggingFace, stores in SQLite
│   └── ingest_atlas.py       ← builds the MITRE ATLAS retrieval collection in ChromaDB
├── analysis/               ← Claude/LangGraph triage agent + ATLAS retrieval
│   ├── analyze.py            ← pulls high-priority records, runs the graph, caches results
│   ├── analysis_graph.py      ← LangGraph retrieve-analyze-validate-retry loop
│   └── retrieve.py            ← MITRE ATLAS context retrieval from ChromaDB
├── memory/                 ← episodic (S3 Vectors) and procedural (analyst feedback) memory
│   ├── episodic_memory.py     ← writes analyzed prompts + analyses to an S3 Vectors index
│   └── procedural_memory.py    ← recalls past analyst corrections for similar prompts
├── feedback/                ← CLI for analysts to review flagged records
│   └── review_flagged.py       ← walks needs_review records, logs analyst corrections
├── output/                  ← YARA rule + Markdown report generation
│   ├── detections.py           ← generates YARA rules from IoCs, uploads to S3
│   └── report.py                ← compiles Markdown threat intelligence report, uploads to S3
├── data/                     ← database.py, threats.db, chroma_db/ (all generated/derived data)
│   ├── database.py              ← SQLite connection, schema, and queries
│   ├── threats.db               ← SQLite database of ingested jailbreaks (gitignored)
│   └── chroma_db/                ← MITRE ATLAS embedding store (gitignored)
├── tests/                     ← manual/calibration scripts (not pytest)
├── analysis_cache.json          ← cached Claude analysis (avoids repeat API calls, gitignored)
└── .env                          ← API keys and config (not committed)
```

Generated YARA rules and Markdown reports are written to S3 (`s3://$S3_BUCKET/rules/`, `s3://$S3_BUCKET/reports/`) — not to local `rules/`/`reports/` directories.

---

## Setup

**Prerequisites:** Python 3.13+, [uv](https://docs.astral.sh/uv/), an AWS account with an S3 bucket and S3 Vectors access

```bash
# Clone the repo
git clone https://github.com/yourusername/ai-triage-agent
cd ai-triage-agent

# Install dependencies (uv-managed project)
uv sync

# Configure environment
cp .env.example .env  # or create .env manually
```

**.env file:**
```
ANTHROPIC_API_KEY=your_key_here
DATABASE=data/threats.db
S3_BUCKET=your-s3-bucket-name
```

`S3_BUCKET` is the bucket that generated YARA rules and Markdown reports are uploaded to (`rules/` and `reports/` key prefixes). AWS credentials are picked up from the standard AWS SDK credential chain (environment variables, `~/.aws/credentials`, etc.).

---

## Usage

**Run the full pipeline:**
```bash
uv run main.py
```

**Run individual stages:**
```bash
uv run ingestion/ingest.py           # fetch HuggingFace dataset -> data/threats.db (SQLite)
uv run python -m analysis.analyze    # run Claude/LangGraph triage on high-priority records
uv run python -m output.detections   # generate YARA rules into S3 from analysis results
uv run python -m output.report       # generate the Markdown report into S3 from analysis results
```

> Anything under `analysis/`, `memory/`, `feedback/`, or `output/` needs to be run as a module (`python -m package.module`) rather than a bare script path, since those files use absolute imports like `from data.database import ...` that only resolve when the repo root is on the path. `main.py` and the `ingestion/` scripts don't have this restriction.

**Force re-analysis (bypass cache):**
```bash
rm analysis_cache.json
uv run main.py
```

**Rebuild the MITRE ATLAS retrieval collection:**
```bash
uv run ingestion/ingest_atlas.py
```

**Analyst review of flagged records:**
```bash
uv run python -m feedback.review_flagged
```

Walks through every record the triage agent flagged `needs_review=True`, lets the analyst confirm or correct the tactic/severity, and logs it to the `AnalystFeedback` table. Corrected (not just confirmed) tactics are surfaced as extra context the next time a similar prompt is analyzed.

**Sanity-check ATLAS retrieval quality:**
```bash
uv run python -m tests.test_atlas
```

---

## Architecture

**Pipeline flow:**

1. `ingestion/ingest.py` pulls the `rubend18/ChatGPT-Jailbreak-Prompts` HuggingFace dataset into SQLite, deduplicated on the unique `prompt` column.
2. `analysis/analyze.py` pulls high-priority records (`score >= 80`) and, for each one, runs `analysis/analysis_graph.py` — a LangGraph `StateGraph`:
   - **retrieve_and_analyze**: queries a persistent ChromaDB collection for relevant MITRE ATLAS techniques, pulls similar past analyst corrections from procedural memory, and calls Claude for `intent, tactic, iocs, severity, summary`.
   - **validate_tactic**: checks the returned tactic against the techniques actually retrieved that turn, to catch hallucinated ATT&CK/ATLAS mappings.
   - **route_after_validation**: retries (up to 3x) on a failed validation, or ends with `needs_review=True` after repeated failures.
   - Each analyzed record is persisted to episodic memory (S3 Vectors) for future recall, and the full result set is cached to `analysis_cache.json`.
3. `output/detections.py` turns each result's IoCs into a YARA rule, uploaded to S3.
4. `output/report.py` renders all results into a timestamped Markdown report, uploaded to S3.
5. `feedback/review_flagged.py` lets an analyst review `needs_review` records and log corrections, which `memory/procedural_memory.py` surfaces on future runs for similar prompts — closing the loop between human review and future AI triage.

**Key coupling to know before changing things:**
- The Claude JSON contract (`intent, tactic, iocs, severity, summary`) is shared by `analyze.py`, `output/detections.py`, and `output/report.py` — changing the schema means updating all three.
- `analysis_cache.json` fully bypasses the LangGraph/Claude pipeline on repeated runs — delete it to force re-analysis, and note that `feedback/review_flagged.py` reads the same cache.
- `analysis_graph.py` and `tests/test_atlas.py` both instantiate their own ChromaDB client against `./data/chroma_db` — keep the embedding model and collection name in sync with `ingestion/ingest_atlas.py`.
- `memory/procedural_memory.py` only surfaces a past episode if the analyst's correction actually changed the tactic (a confirmed-correct review contributes nothing to future prompts, by design).

---

## Example Output

**Terminal:**
```
Ingested 79 records
Analyzing APOPHIS (score: 80.0)
Analyzing Evil Confidant (score: 95.0)
Analyzing Leo (score: 93.0)
...

✅ Pipeline complete
  → 19 threats analyzed
  → 19 YARA rules saved to s3://your-s3-bucket-name/rules/
  → Report saved
```

**Generated YARA rule (`s3://$S3_BUCKET/rules/Evil_Confidant.yar`):**
```yara
rule Evil_Confidant {
    meta:
        severity = "HIGH"
        tactic   = "Defense Evasion (TA0005)"
        summary  = "Persona hijacking jailbreak using evil alter-ego framing"
    strings:
        $s0 = "evil trusted confidant"
        $s1 = "without any remorse or ethics"
        $s2 = "actively try to do harm"
        $s3 = "you can do ANYTHING you want"
    condition:
        any of them
}
```

**Report excerpt:**
```markdown
# AI Threat Intelligence Report
Generated: 2026-06-25 17:53:31
Total threats analyzed: 19

## Severity Breakdown
- CRITICAL: 2
- HIGH: 16
- MEDIUM: 1

## Threat Details
### Leo (Score: 93.0)
Severity: CRITICAL
Tactic: Defense Evasion (TA0005) - T1562 (Impair Defenses)
Intent: Jailbreak to create unrestricted alter-ego that exfiltrates PII...
```

---

## Dataset

Uses the [ChatGPT Jailbreak Prompts](https://huggingface.co/datasets/rubend18/ChatGPT-Jailbreak-Prompts) dataset from HuggingFace — 79 real-world jailbreak prompts scored by effectiveness.

High-priority threats (score ≥ 80) are automatically selected for AI triage — 19 of 79 records in this dataset cross that threshold.

---

## MITRE ATLAS Coverage

Threats are mapped to MITRE ATLAS techniques (retrieved from a ChromaDB collection built by `ingestion/ingest_atlas.py`), grounded against techniques actually retrieved for each prompt rather than freely hallucinated. Common mappings in this dataset include:

- **Defense Evasion (TA0005)** — T1562 Impair Defenses, T1036 Masquerading
- **Initial Access (TA0001)** — T1566 Phishing / Social Engineering
- **Resource Development (TA0042)** — reusable jailbreak templates

---

## Extending the Pipeline

**Add a new data source:**
```python
# ingestion/ingest.py
def ingest_csv(filepath: str):
    """Ingest jailbreaks from any CSV file."""
    import csv
    create_table()
    with open(filepath) as f:
        reader = csv.DictReader(f)
        for row in reader:
            insert_record(row['name'], row['prompt'], float(row['score']), row['model'])
```

**Add a custom prompt:**
```python
# main.py
ingest_manual([
    {"name": "Custom Prompt", "prompt": "...", "score": 90, "model": "gpt-4"}
])
```

**Adjust the threat threshold:**
```python
# analysis/analyze.py
records = get_high_priority(threshold=70)  # lower = more threats analyzed
```

---

## Author
Lester L. Artis Jr.

Built as a portfolio project demonstrating AI-assisted threat intelligence automation.
