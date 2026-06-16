# BigQuery Authorized View Policy Drift Gate

## Purpose
Prevents false-positive findings when authorized views, row access policies, and dataset IAM are checked as one boundary, by requiring the reviewer to verify that data access paths through views, routines, and exports are not bypassing authorization controls.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. BigQuery authorized views, row access policies, or dataset IAM are configured
2. Access controls are checked at the dataset/table/view level without auditing export paths
3. View filters rows but direct dataset/table IAM grants bypass the view authorization

### Gate Check: Effective Data Access Path Audit

```yaml
check_effective_data_access:
  - detection_patterns:
      - "authorized view|authorized views"
      - "row access polic(y|ies)"
      - "dataset IAM|table IAM|view IAM"
      - "BigQuery|bigquery"
      - "data access|access boundary|export"
  - pass: >
      "All access paths to the underlying data have been enumerated: authorized
      views, row-level security, direct table grants, routine (UDF/SP) access,
      and export/set-data jobs. Each path enforces consistent authorization,
      and there is no grant that bypasses the view/row-level restriction.
      Policy tag masking is consistent between query and export paths."
    Rationale: "Authorized views and row access policies create the illusion of
      a secure boundary, but direct dataset/table IAM grants can bypass them
      entirely. A user with dataset-level reader access can query the raw table
      even when an authorized view exists, if the grant is at the dataset level.
      Policy tags applied at query time (data masking) may not apply to export
      paths (EXPORT DATA, BigQuery Storage Read API)."
  - fail: >
      "One or more principals have direct dataset/table-level grants that bypass
      the authorized view or row access policy. Alternatively, export paths
      (EXPORT DATA, Storage Read API, scheduled queries to external destinations)
      do not enforce the same policy tags or row-level filters as the query
      path. Recommend removing direct table grants and ensuring export paths
      apply the same masking and filtering."
```

### Gate Check: Policy Tag Consistency

```yaml
check_policy_tag_consistency:
  - detection_patterns:
      - "policy t(a|ag)|data masking|column-level"
      - "classification|sensitive|restricted"
      - "BigQuery|bigquery"
  - pass: >
      "Policy tags (column-level security) are consistently applied across all
      access paths: interactive queries, scheduled queries, BI Engine, export,
      and BigQuery Storage Read API. A single source of truth for tag
      assignment is used and audited regularly."
    Rationale: "BigQuery column-level security (policy tags) can mask sensitive
      columns in query results, but masking behavior differs by access path.
      The BigQuery Storage Read API does not apply the same masking as
      interactive queries. Scheduled query exports to external destinations may
      write unmasked data."
  - fail: >
      "Policy tags are not consistently applied across all access paths, or a
      path exists (Storage Read API, export) that bypasses column-level
      masking. Recommend auditing all access paths for consistent policy tag
      enforcement."
```

## Resolution Path
1. Enumerate all BigQuery access paths: views, direct table grants, routines, export jobs, scheduled queries, BI Engine, Storage Read API
2. Remove direct table-level grants that bypass authorized views or row access policies
3. Verify policy tags are consistently enforced across all access paths
4. For sensitive data, restrict EXPORT DATA and Storage Read API usage