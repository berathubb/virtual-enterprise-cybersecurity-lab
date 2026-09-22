#!/usr/bin/env python3
"""
Wazuh Indexer Client
Virtual Enterprise Cybersecurity Lab - Phase 4 Automation

Wazuh Indexer (OpenSearch) API'sini kullanarak gerçek alert'leri çeker.
"""

import requests
import json
import urllib3
import sys
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from collections import Counter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhIndexerClient:
    """Wazuh Indexer (OpenSearch) API client"""
    
    def __init__(self, host: str, username: str, password: str):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.auth = (username, password)
    
    def search_alerts(self, size: int = 100, query: dict = None) -> List[Dict]:
        """
        Alert'leri ara.
        
        Args:
            size: Kaç alert dönsün
            query: Elasticsearch query (opsiyonel)
        """
        if query is None:
            query = {"match_all": {}}
        
        url = f"{self.host}/wazuh-alerts-*/_search"
        params = {
            "size": size,
            "sort": "@timestamp:desc"
        }
        body = {"query": query}
        
        response = requests.post(
            url,
            params=params,
            json=body,
            auth=self.auth,
            verify=False,
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        
        return [hit['_source'] for hit in data['hits']['hits']]
    
    def count_by_rule_level(self) -> Dict:
        """Rule level'a göre sayım yap"""
        url = f"{self.host}/wazuh-alerts-*/_search"
        body = {
            "size": 0,
            "aggs": {
                "by_level": {
                    "terms": {"field": "rule.level", "size": 20}
                }
            }
        }
        response = requests.post(
            url, json=body, auth=self.auth, verify=False, timeout=30
        )
        response.raise_for_status()
        data = response.json()
        return data['aggregations']['by_level']['buckets']
    
    def count_by_agent(self) -> Dict:
        """Agent'a göre sayım yap"""
        url = f"{self.host}/wazuh-alerts-*/_search"
        body = {
            "size": 0,
            "aggs": {
                "by_agent": {
                    "terms": {"field": "agent.name", "size": 20}
                }
            }
        }
        response = requests.post(
            url, json=body, auth=self.auth, verify=False, timeout=30
        )
        response.raise_for_status()
        data = response.json()
        return data['aggregations']['by_agent']['buckets']
    
    def count_by_rule(self) -> Dict:
        """Rule ID'ye göre sayım yap"""
        url = f"{self.host}/wazuh-alerts-*/_search"
        body = {
            "size": 0,
            "aggs": {
                "by_rule": {
                    "terms": {
                        "field": "rule.id",
                        "size": 20,
                        "order": {"_count": "desc"}
                    }
                }
            }
        }
        response = requests.post(
            url, json=body, auth=self.auth, verify=False, timeout=30
        )
        response.raise_for_status()
        data = response.json()
        return data['aggregations']['by_rule']['buckets']


def main():
    """Ana fonksiyon - demo"""
    
    # Config (docker-compose.yml'den)
    INDEXER_HOST = "https://10.10.10.50:9200"
    INDEXER_USER = "admin"
    INDEXER_PASS = "SecretPassword"
    
    print("=" * 70)
    print("Wazuh Indexer Client - Phase 4 Automation")
    print("=" * 70)
    print(f"Time: {datetime.now().isoformat()}")
    print()
    
    client = WazuhIndexerClient(INDEXER_HOST, INDEXER_USER, INDEXER_PASS)
    
    # 1. Son 10 alert'i çek
    print("[1] Son 10 Alert:")
    print("-" * 70)
    alerts = client.search_alerts(size=10)
    for alert in alerts:
        ts = alert.get('@timestamp', 'N/A')[:19]
        rule = alert.get('rule', {})
        agent = alert.get('agent', {})
        rule_id = rule.get('id', 'N/A')
        level = rule.get('level', 'N/A')
        desc = rule.get('description', 'N/A')[:50]
        agent_name = agent.get('name', 'N/A')
        print(f"    {ts} | L{level} | Rule {rule_id:<6} | {agent_name:<10} | {desc}")
    print()
    
    # 2. Rule level dağılımı
    print("[2] Rule Level Dağılımı:")
    print("-" * 70)
    levels = client.count_by_rule_level()
    for bucket in levels:
        print(f"    Level {bucket['key']:<3} : {bucket['doc_count']:>6} alert")
    print()
    
    # 3. Agent dağılımı
    print("[3] Agent Dağılımı:")
    print("-" * 70)
    agents = client.count_by_agent()
    for bucket in agents:
        print(f"    {bucket['key']:<20} : {bucket['doc_count']:>6} alert")
    print()
    
    # 4. En çok tetiklenen rule'lar (Top 10)
    print("[4] En Çok Tetiklenen Rule'lar (Top 10):")
    print("-" * 70)
    rules = client.count_by_rule()
    for bucket in rules[:10]:
        print(f"    Rule {bucket['key']:<8} : {bucket['doc_count']:>6} tetiklenme")
    print()
    
    print("=" * 70)
    print(" Script completed successfully")
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n ERROR: {e}", file=sys.stderr)
        sys.exit(1)
