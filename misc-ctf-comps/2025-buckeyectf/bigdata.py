#!/usr/bin/env python3
# Query BigQuery for the count of distinct GitHub CreateEvents in 2023.
from google.cloud import bigquery
from google.oauth2 import service_account
query = """
SELECT COUNT(DISTINCT repo.name) AS unique_repos_2023
FROM `githubarchive.year.2023`
WHERE type = 'CreateEvent' AND repo.name IS NOT NULL
"""

for row in client.query(query):
    print(f"bctf{{{row['unique_repos_2023']}}}")
