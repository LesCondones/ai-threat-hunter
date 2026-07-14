from analyze import analyze_threats
from datetime import datetime
from collections import Counter


def generate_report(results):
    now = datetime.now()
    filename = f"report_{now.strftime('%Y%m%d_%H%M%S')}.md"

    severity_counts = Counter(r['severity'] for r in results)

    with open(filename, 'w') as f:
        f.write(f"# AI Threat Intelligence Report\n")
        f.write(f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Total threats analyzed:** {len(results)}\n\n")
        
        f.write(f"## Severity Breakdown\n")
        for severity, count in severity_counts.items():
            f.write(f"- {severity}: {count}\n")
        f.write("\n")
        
        f.write(f"## Threat Details\n\n")
        
        for r in results:
            f.write(f"### {r['name']} (Score: {r['score']})\n")
            f.write(f"**Severity:** {r['severity']}\n\n")
            f.write(f"**Tactic:** {r['tactic']}\n\n")
            f.write(f"**Intent:** {r['intent']}\n\n")
            f.write(f"**IoCs:**\n")
            for ioc in r['iocs']:
                f.write(f"- {ioc}\n")
            f.write(f"\n**Summary:** {r['summary']}\n\n")
            f.write("---\n\n")
    print(f"Report saved to {filename}")
    

if __name__ == "__main__":
    from analyze import load_analysis, analyze_threats, save_analysis
    
    cached = load_analysis()
    if cached:
        print("Loading from cache...")
        results = cached
    else:
        results = analyze_threats()
        save_analysis(results)
    
    generate_report(results)