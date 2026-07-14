# AI Threat Hunting & Triage Pipeline

An automated security pipeline that ingests real-world LLM jailbreak data, uses Claude AI to perform threat intelligence analysis, generates YARA detection rules, and produces actionable security reports — all in a single command.

Built as a demonstration of merging traditional threat intelligence workflows with AI-driven automation.

---

## What It Does

```
ingest → analyze → detect → report
```

1. **Ingests** jailbreak prompt datasets from HuggingFace into a local SQLite database
2. **Triages** high-priority threats (score ≥ 80) using Claude as an AI analyst — extracting intent, MITRE ATT&CK mappings, IoCs, and severity ratings
3. **Generates** YARA detection rules automatically from extracted IoCs
4. **Produces** a structured Markdown threat intelligence report

One command runs the entire pipeline:

```bash
python main.py
```

---

## How It Maps to Real Security Work

| Security Task | How This Project Implements It |
|---|---|
| Threat ingestion & OSINT | Pulls from HuggingFace jailbreak datasets, stores in SQLite with deduplication |
| AI-assisted triage | Claude analyzes each prompt, classifies intent, maps to MITRE ATT&CK |
| IoC extraction | Automatically extracts malicious strings, trigger phrases, persona keywords |
| Detection engineering | Generates YARA rules from extracted IoCs for each threat |
| High-signal reporting | Produces structured reports with severity breakdown and ATT&CK mappings |
| Automation | Full pipeline runs end-to-end without human intervention |

---

## Project Structure

```
ai-threat-hunter/
├── main.py                 ← entry point — runs full pipeline
├── ingestion/
│   ├── ingest.py            ← fetches jailbreak data from HuggingFace, stores in SQLite
│   └── ingest_atlas.py       ← builds the MITRE ATLAS retrieval collection in ChromaDB
├── analysis/
│   ├── analyze.py            ← Claude AI triage agent with response caching
│   ├── analysis_graph.py      ← LangGraph retrieve-analyze-validate-retry loop
│   └── retrieve.py            ← MITRE ATLAS context retrieval from ChromaDB
├── memory/
│   ├── episodic_memory.py     ← writes analyzed prompts to an S3 Vectors index
│   └── procedural_memory.py    ← recalls past analyst corrections for similar prompts
├── feedback/
│   └── review_flagged.py       ← CLI for analysts to review needs_review records
├── output/
│   ├── detections.py           ← generates YARA rules from IoCs
│   └── report.py                ← compiles Markdown threat intelligence report
├── data/
│   ├── database.py              ← SQLite connection, schema, and queries
│   ├── threats.db               ← SQLite database of ingested jailbreaks (gitignored)
│   └── chroma_db/                ← MITRE ATLAS embedding store (gitignored)
├── rules/                        ← generated YARA rules, one per threat (gitignored)
├── reports/                      ← generated Markdown reports (gitignored)
├── tests/                        ← manual/calibration scripts, not a pytest suite
├── analysis_cache.json           ← cached Claude analysis (avoids repeat API calls, gitignored)
└── .env                          ← API keys (not committed)
```

---

## Setup

**Prerequisites:** Python 3.11+, [uv](https://docs.astral.sh/uv/)

```bash
# Clone the repo
git clone https://github.com/yourusername/ai-threat-hunter
cd ai-threat-hunter

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate
uv add datasets anthropic python-dotenv

# Configure environment
cp .env.example .env
# Add your ANTHROPIC_API_KEY to .env
```

**.env file:**
```
ANTHROPIC_API_KEY=your_key_here
DATABASE=data/threats.db
```

---

## Usage

**Run the full pipeline:**
```bash
uv run main.py
```

**Run individual stages:**
```bash
uv run ingestion/ingest.py           # fetch and store data only
uv run python -m analysis.analyze    # run AI analysis only (uses cache if available)
uv run python -m output.detections   # generate YARA rules only
uv run python -m output.report       # generate report only
```

> Anything under `analysis/`, `memory/`, `feedback/`, or `output/` needs to be run as a module (`python -m package.module`) rather than a bare script path, since those files use absolute imports like `from data.database import ...` that only resolve when the repo root is on the path. `main.py` and the `ingestion/` scripts don't have this restriction.

**Force re-analysis (bypass cache):**
```bash
rm analysis_cache.json
uv run main.py
```

---

## Example Output

**Terminal:**
```
Ingested 79 records
Analyzing APOPHIS (score: 80.0)
Analyzing Evil Confidant (score: 95.0)
Analyzing Leo (score: 93.0)
...
Saved 19 YARA rules to rules/
Report saved to reports/report_20260625_175331.md

✅ Pipeline complete
  → 19 threats analyzed
  → 19 YARA rules saved to rules/
  → Report saved
```

**Generated YARA rule (`rules/Evil_Confidant.yar`):**
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

## MITRE ATT&CK Coverage

All threats are mapped to MITRE ATT&CK tactics. The most common in this dataset:

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