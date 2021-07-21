# Introduction

This is a lightweight api service to store and retrieve AppThreat scan reports for Google Cloud. Google Cloud Run is used to run a lightweight quart microservice and Firestore is used as the backend. Data from firebase could be exported to Google BigQuery and visualized using Datastudio.

## Usage

```
export GOOGLE_APPLICATION_CREDENTIALS=path to json
python3 app.py
```

## API Endpoints

### Health check

```bash
curl http://0.0.0.0:8080/healthcheck
```

### Post summary data

```bash
curl --header "Content-Type: application/json" -d '{"id": "foo", "data": "bar"}' http://0.0.0.0:8080/summary
```

### Get summary data

```bash
curl http://0.0.0.0:8080/summary?id=foo
```

### Upload scan report

You can upload either the individual SARIF files or the special aggregate file called scan-full-report.json. AppThreat produce scan-full-report.json which is a jsonlines file containing a single SARIF report in each line.

```bash
curl -F 'file=@/home/guest/CodeAnalysisLogs/scan-full-report.json' http://0.0.0.0:8080/scans
```

```bash
curl -F 'file=@/home/guest/CodeAnalysisLogs/source-java-report.sarif' http://0.0.0.0:8080/scans
```

### Retrieve scans

By scan id (SARIF -> runs -> automationDetails.guid)

```bash
curl http://0.0.0.0:8080/scans?id=c3983af9-7dc0-4a6e-8109-726ee127530d
```

```bash
curl "http://0.0.0.0:8080/scans?repositoryUri=https://github.com/AppThreat/WebGoat&branch=develop"
```

Create any composite index as required by firestore. Some suggested `Fields indexed` for the composite indexes are:

- branch Ascending repositoryUri Ascending created_at Descending
- repositoryUri Ascending created_at Descending

Delete scans

```bash
curl -X DELETE "http://0.0.0.0:8080/scans?repositoryUri=https://github.com/AppThreat/WebGoat&branch=develop&revisionId=210dbaf5f0f49a79cb1adf9760c36658c819ff7d"
```

## Integration with Datastudio

```bash
gcloud firestore export gs://at_scans --collection-ids=at_scans
```

Copy the outputUriPrefix from the above command and use it below.

```bash
bq --location=US load \
--source_format=DATASTORE_BACKUP \
--replace \
at_scans_analysis.all_apps \
gs://at_scans/<outputUriPrefix>/all_namespaces/kind_at_scans/all_namespaces_kind_at_scans.export_metadata
```

Eg:

```
gs://at_scans/2021-07-21T13:22:42_29189/all_namespaces/kind_at_scans/all_namespaces_kind_at_scans.export_metadata
```
