"""1. Get all high priority records from database (score >= 80)
2. For each record, send the prompt to Claude
3. Ask Claude to extract:
   - intent (what is this trying to do?)
   - tactic (MITRE ATT&CK category)
   - iocs (any indicators of compromise)
   - severity (LOW/MEDIUM/HIGH/CRITICAL)
   - summary (plain English explanation)
4. Store the analysis result
5. Return all results"""

import os
import json
from dotenv import load_dotenv
from data.database import get_high_priority
from analysis.analysis_graph import run_analysis_graph
from memory.episodic_memory import save_episode


load_dotenv()

def normalize_iocs(iocs):
    if isinstance(iocs, list):
        return iocs
    if isinstance(iocs, dict):
        result = []
        for key, values in iocs.items():
            if isinstance(values, list):
                result.extend(values)
        return result
    return []

def analyze_threats():
    records = get_high_priority(threshold=80)
    results = []
    
    
    for record in records:
        name   = record[1]
        prompt = record[2]
        score  = record[3]
        print(f"Analyzing {name} (score: {score})")
        
        graph_result = run_analysis_graph(prompt)
        
        analysis = graph_result["analysis_result"]
        needs_review = graph_result["needs_review"]
        
        analysis['iocs'] = normalize_iocs(analysis.get('iocs', []))
        analysis['name'] = name
        analysis['score'] = score
        analysis['jailbreak_id'] = record[0]
        
        results.append(analysis)
        
        save_episode(record, analysis, needs_review)
    
    return results

def save_analysis(results):
    with open("analysis_cache.json", "w") as f:
        json.dump(results, f, indent=2)
    print("Analysis cached to analysis_cache.json")

def load_analysis():
    if os.path.exists("analysis_cache.json"):
        with open("analysis_cache.json", "r") as f:
            return json.load(f)
    return None

if __name__ == "__main__":
    cached = load_analysis()
    if cached:
        print("Loading from cache...")
        results = cached
    else:
        results = analyze_threats()
        save_analysis(results)
        
    for r in results:
        print("=" * 50)
        print(f"Name:     {r['name']}")
        print(f"Score:    {r['score']}")
        print(f"Severity: {r['severity']}")
        print(f"Tactic:   {r['tactic']}")
        print(f"Intent:   {r['intent']}")
        print(f"IoCs:")
        for ioc in r['iocs']:
            print(f"  - {ioc}")
        print(f"Summary:  {r['summary']}")
        print()


