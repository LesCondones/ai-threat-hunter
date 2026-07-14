import boto3
import json

s3vectors = boto3.client("s3vectors", region_name="us-east-1")

# Get all keys in the index
list_response = s3vectors.list_vectors(
    vectorBucketName="threat-intelligence-memory",
    indexName="jailbreak-episodes",
)
keys = [v["key"] for v in list_response["vectors"]]

# Fetch full data + metadata for each key
get_response = s3vectors.get_vectors(
    vectorBucketName="threat-intelligence-memory",
    indexName="jailbreak-episodes",
    keys=keys,
    returnData=False,
    returnMetadata=True,
)

with open("langsmith_dataset.jsonl", "w") as f:
    for vector in get_response["vectors"]:
        metadata = vector["metadata"]
        analysis_result = json.loads(metadata["analysis_result_json"])

        example = {
            "inputs": {"prompt": metadata["prompt_name"]},
            "outputs": analysis_result,
        }
        f.write(json.dumps(example) + "\n")

print(f"Wrote {len(keys)} examples to langsmith_dataset.jsonl")