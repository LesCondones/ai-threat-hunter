import boto3
import json
from chromadb.utils import embedding_functions

s3vectors = boto3.client("s3vectors", region_name="us-east-1")
embedder = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )

def save_episode(record, analysis_result, needs_review):
    """Embeds the original jailbreak prompt and writes it, plus the full
    analysis result, into the jailbreak_episodes vector index for future
    similarity-based recall."""

    record_id = record[0]
    name = record[1]
    prompt = record[2]
    score = record[3]

    embedding = embedder(input=[prompt])[0].tolist() # returns a list of floats

    s3vectors.put_vectors(
        vectorBucketName="threat-intelligence-memory",
        indexName="jailbreak-episodes",
        vectors=[
            {
                "key": str(record_id),
                "data": {"float32": embedding},
                "metadata": {
                    "prompt_name": name,
                    "score": score,
                    "analysis_result_json": json.dumps(analysis_result),
                    "needs_review": needs_review,
                },
            }
        ],
    )