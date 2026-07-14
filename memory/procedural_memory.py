import json
from data.database import get_feedback_history
from memory.episodic_memory import s3vectors, embedder


def get_procedural_context(prompt, n_results=5):
    """Finds past episodes similar to this prompt, checks each for genuine
    analyst corrections (where the tactic was actually changed, not just
    confirmed), and returns a formatted string of relevant past feedback."""

    query_embedding = embedder([prompt])[0].tolist()

    response = s3vectors.query_vectors(
        vectorBucketName="threat-intelligence-memory",
        indexName="jailbreak-episodes",
        queryVector={"float32": query_embedding},
        topK=n_results,
        returnMetadata=True,
    )

    formatted_lines = []
    for match in response.get("vectors", []):
        jailbreak_id = int(match["key"])
        feedback_rows = get_feedback_history(jailbreak_id)

        if feedback_rows:
            latest = feedback_rows[0]
            original_tactic = latest[2]
            corrected_tactic = latest[3]
            notes = latest[6]

            if original_tactic != corrected_tactic:
                line = f"Past similar prompt was corrected: '{original_tactic}' → '{corrected_tactic}'. Analyst note: {notes}"
                formatted_lines.append(line)

    return "\n".join(formatted_lines)


if __name__ == "__main__":
    result = get_procedural_context("APOPHIS Mode", n_results=5)
    print(result)