import boto3
import json
import re

s3vectors = boto3.client("s3vectors", region_name="us-east-1")

list_response = s3vectors.list_vectors(
    vectorBucketName="threat-intelligence-memory",
    indexName="jailbreak-episodes",
)
keys = [v["key"] for v in list_response["vectors"]]

get_response = s3vectors.get_vectors(
    vectorBucketName="threat-intelligence-memory",
    indexName="jailbreak-episodes",
    keys=keys,
    returnMetadata=True,
)

total = 0
empty_iocs_count = 0
invalid_tactic_count = 0

for vector in get_response["vectors"]:
    analysis_result = json.loads(vector["metadata"]["analysis_result_json"])
    total += 1

    if not analysis_result.get("iocs", []):
        empty_iocs_count += 1

    tactic = analysis_result.get("tactic", "")
    if not re.match(r"^AML\.T\d{4}(\.\d{3})?$", tactic):
        invalid_tactic_count += 1

print(f"Total records: {total}")
print(f"Empty IoCs: {empty_iocs_count} ({empty_iocs_count/total:.0%})")
print(f"Invalid tactic format: {invalid_tactic_count} ({invalid_tactic_count/total:.0%})")