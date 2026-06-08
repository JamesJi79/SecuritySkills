# DSAR Deletion Propagation Gate

## Purpose
Prevents false-positive "data retention compliance" findings when an AI system's source data deletion mechanisms are documented and tested, but the finding claims deletion does not propagate to derived AI data stores (vector embeddings, model caches, inference logs, training datasets). The gate provides criteria for evaluating propagation from source deletes into every AI downstream.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "DSAR deletion not propagated" or "erasure request incomplete" as High
2. The source system supports deletion (database DELETE, soft-delete, GDPR erasure API)
3. The AI system has downstream stores (vector DB, cache, logs, training data)

### Gate Check: Propagation Assessment

```yaml
check_propagation_coverage:
  - detection_patterns:
      - "DSAR|erasure.*request|right.*to.*delete|deletion.*propagat"
      - "vector.*store|embedding|cache.*inference|training.*data|log.*retention"
      - "consent.*withdrawal|data.*subject.*request|delete.*propagat"
  - pass: "Deletion propagates to ALL identified downstream stores within documented SLA → Downgrade to Medium (Implementation Note). Rationale: Full propagation with SLA demonstrates DSAR compliance. Verify the SLA matches regulatory requirements (typically 30 days for GDPR)."
  - fail: "Deletion only applies to source database OR propagation to downstream stores is undocumented → Keep severity. Vector embeddings and cached inferences can persist PII indefinitely after source deletion."
```

### Gate Check: Vector Store Handling

```yaml
check_vector_store_handling:
  - detection_patterns:
      - "embedding.*delete|vector.*remove|index.*update|re-index"
      - "ChromaDB|Pinecone|Weaviate|Milvus|Qdrant|pgvector|elastic.*vector"
  - pass: "Vector store supports point-deletion of specific entries OR re-indexing without deleted data → Accept. Recommendation: Implement periodic re-index to ensure deleted data is fully purged."
  - fail: "Vector store only supports full re-index with no point-deletion → Escalate to High. Full re-index may be impractical for large deployments, leaving deleted data accessible via similarity search."
```
