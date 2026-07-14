def retrieve_atlas_context(collection, prompt, n_results=6, max_distance = 0.85):
    """Query the ATLAS collection for entries similar to the given prompt."""
    response = collection.query(
        query_texts=[prompt],
        n_results=n_results,
    )

    results = []
    for text, metadata, distance in zip(
        response["documents"][0],
        response["metadatas"][0],
        response["distances"][0],
    ):
      if distance <= max_distance:
        results.append({
            "text": text,
            "metadata": metadata,
            "distance": distance,
        }) 
          

    return results