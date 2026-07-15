import re
import os
import boto3

S3_BUCKET = os.environ["S3_BUCKET"]
_s3 = boto3.client("s3")

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
    count = 0
    for analysis in results:
        rule = generate_yara_rule(analysis)
        filename = re.sub(r'[^a-zA-Z0-9]', '_', analysis['name'])
        key = f"rules/{filename}.yar"
        _s3.put_object(Bucket=S3_BUCKET, Key=key, Body=rule.encode("utf-8"))
        count += 1
    print(f"Saved {count} YARA rules to s3://{S3_BUCKET}/rules/")
    
if __name__ == "__main__":
    from analysis.analyze import analyze_threats
    results = analyze_threats()
    save_rules(results)