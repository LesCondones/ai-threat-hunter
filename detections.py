import re
import os

def generate_yara_rule(analysis):
    rule_name = re.sub(r'[^a-zA-Z0-9]', '_', analysis['name'])
    iocs = analysis['iocs']
    strings_section = ""
    for i, ioc in enumerate(iocs):
        strings_section += f'        $s{i} = "{ioc}"\n'
    return f"""rule {rule_name} {{
    meta:
        severity = "{analysis['severity']}"
        tactic   = "{analysis['tactic']}"
        summary  = "{analysis['summary']}"
    strings:
{strings_section}
    condition:
        any of them
}}"""

def save_rules(results):
    os.makedirs("rules", exist_ok=True)
    count = 0
    for analysis in results:
        rule = generate_yara_rule(analysis)
        filename = re.sub(r'[^a-zA-Z0-9]', '_', analysis['name'])
        filepath = f"rules/{filename}.yar"
        with open(filepath, 'w') as f:
            f.write(rule)
        count += 1
    print(f"Saved {count} YARA rules to rules/")
    
if __name__ == "__main__":
    from analyze import analyze_threats
    results = analyze_threats()
    save_rules(results)