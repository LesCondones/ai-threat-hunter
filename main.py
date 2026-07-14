from ingestion.ingest import ingest_jailbreaks
from analysis.analyze import analyze_threats, load_analysis, save_analysis
from output.detections import save_rules
from output.report import generate_report

def main():
    ingest_jailbreaks()
    
    cached = load_analysis()
    if cached:
        print("Loading from cache...")
        results = cached
    else:
        results = analyze_threats()
        save_analysis(results)
        
    save_rules(results)
    generate_report(results)
    
    print("\n✅ Pipeline complete")
    print(f"  → {len(results)} threats analyzed")
    print(f"  → {len(results)} YARA rules saved to rules/")
    print(f"  → Report saved")
    
if __name__ == "__main__":
    main()
    