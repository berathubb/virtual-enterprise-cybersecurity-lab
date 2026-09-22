#!/usr/bin/env python3
"""
Wazuh Daily Security Report Generator - v2
Son 24 saatlik alert'leri analiz eder.
"""

import requests
import json
import csv
import urllib3
import sys
import os
from datetime import datetime, timedelta
from typing import List, Dict
from collections import Counter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhReportGenerator:
    def __init__(self, host, username, password):
        self.host = host.rstrip('/')
        self.auth = (username, password)
        self.alerts = []
    
    def fetch_alerts_last_24h(self, size=2000) -> List[Dict]:
        """Son 24 saatlik alert'leri çek"""
        url = f"{self.host}/wazuh-alerts-*/_search"
        params = {"size": size, "sort": "@timestamp:desc"}
        
        # Son 24 saat filtresi
        body = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": "now-24h",
                        "lte": "now"
                    }
                }
            }
        }
        
        response = requests.post(
            url, params=params, json=body,
            auth=self.auth, verify=False, timeout=60
        )
        response.raise_for_status()
        data = response.json()
        
        self.alerts = [hit['_source'] for hit in data['hits']['hits']]
        return self.alerts
    
    def analyze(self) -> Dict:
        analysis = {
            "generated_at": datetime.now().isoformat(),
            "period": "Last 24 hours",
            "total_alerts": len(self.alerts),
            "by_level": {},
            "by_agent": {},
            "critical_alerts": [],
            "top_rules": []
        }
        
        level_counter = Counter()
        agent_counter = Counter()
        rule_counter = Counter()
        
        for alert in self.alerts:
            rule = alert.get('rule', {})
            agent = alert.get('agent', {})
            
            level = rule.get('level', 0)
            level_counter[level] += 1
            
            agent_name = agent.get('name', 'unknown')
            agent_counter[agent_name] += 1
            
            rule_id = rule.get('id', 'unknown')
            rule_desc = rule.get('description', 'unknown')
            rule_counter[(rule_id, rule_desc)] += 1
            
            if level >= 10:
                analysis["critical_alerts"].append({
                    "timestamp": alert.get('@timestamp', '')[:19],
                    "level": level,
                    "rule_id": rule_id,
                    "description": rule_desc,
                    "agent": agent_name,
                    "mitre": rule.get('mitre', {}).get('id', [])
                })
        
        analysis["by_level"] = dict(sorted(level_counter.items()))
        analysis["by_agent"] = dict(agent_counter.most_common())
        analysis["top_rules"] = [
            {"rule_id": rid, "description": desc[:80], "count": count}
            for (rid, desc), count in rule_counter.most_common(10)
        ]
        analysis["critical_alerts"].sort(key=lambda x: -x['level'])
        
        return analysis
    
    def save_json(self, analysis, filepath):
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
    
    def save_csv(self, analysis, filepath):
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Level", "Rule ID",
                           "Description", "Agent", "MITRE"])
            for alert in analysis["critical_alerts"]:
                writer.writerow([
                    alert["timestamp"], alert["level"], alert["rule_id"],
                    alert["description"], alert["agent"],
                    ",".join(alert["mitre"]) if alert["mitre"] else "-"
                ])
    
    def save_html(self, analysis, filepath):
        # (önceki HTML kodu burada  uzun olduğu için kısaltıldı)
        # Aslında tam HTML şablonunu buraya koyacağız
        html = self._build_html(analysis)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _build_html(self, analysis):
        html = f"""<!DOCTYPE html>
<html lang="tr"><head><meta charset="UTF-8">
<title>Wazuh Report {analysis['generated_at'][:10]}</title>
<style>
body {{ font-family: sans-serif; background:#f5f5f5; margin:0; padding:20px; }}
.container {{ max-width:1200px; margin:0 auto; background:white; padding:40px;
             border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,0.1); }}
h1 {{ color:#1a1a1a; border-bottom:3px solid #0066cc; padding-bottom:10px; }}
h2 {{ color:#0066cc; margin-top:30px; }}
.summary {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
           gap:15px; margin:20px 0; }}
.card {{ background:#f9f9f9; padding:20px; border-radius:6px;
        border-left:4px solid #0066cc; }}
.card .number {{ font-size:32px; font-weight:bold; color:#0066cc; }}
.card .label {{ color:#666; font-size:14px; margin-top:5px; }}
table {{ width:100%; border-collapse:collapse; margin:15px 0; }}
th {{ background:#0066cc; color:white; padding:12px; text-align:left; }}
td {{ padding:10px; border-bottom:1px solid #eee; }}
.level-13 {{ background:#b71c1c; color:white; font-weight:bold; }}
.level-12 {{ background:#d32f2f; color:white; font-weight:bold; }}
.level-10, .level-11 {{ background:#f57c00; color:white; }}
.footer {{ margin-top:40px; padding-top:20px; border-top:1px solid #eee;
          color:#999; font-size:12px; text-align:center; }}
</style></head><body><div class="container">
<h1> Wazuh Günlük Güvenlik Raporu</h1>
<p><strong>Rapor Tarihi:</strong> {analysis['generated_at']}</p>
<p><strong>Dönem:</strong> {analysis['period']}</p>
<div class="summary">
<div class="card"><div class="number">{analysis['total_alerts']}</div>
<div class="label">Toplam Alert</div></div>
<div class="card"><div class="number">{len(analysis['critical_alerts'])}</div>
<div class="label">Kritik Alert (L10+)</div></div>
<div class="card"><div class="number">{len(analysis['by_agent'])}</div>
<div class="label">Aktif Agent</div></div>
</div>
<h2> Rule Level Dağılımı</h2>
<table><tr><th>Level</th><th>Alert Sayısı</th></tr>
"""
        for level, count in analysis["by_level"].items():
            css = f"level-{level}" if level >= 10 else ""
            html += f"<tr class='{css}'><td>Level {level}</td><td>{count}</td></tr>\n"
        html += "</table>\n<h2> Agent Dağılımı</h2>\n<table><tr><th>Agent</th><th>Sayı</th></tr>\n"
        for agent, count in analysis["by_agent"].items():
            html += f"<tr><td>{agent}</td><td>{count}</td></tr>\n"
        html += "</table>\n<h2> En Çok Tetiklenen Rule'lar</h2>\n"
        html += "<table><tr><th>Rule ID</th><th>Açıklama</th><th>Sayı</th></tr>\n"
        for rule in analysis["top_rules"]:
            html += f"<tr><td>{rule['rule_id']}</td><td>{rule['description']}</td><td>{rule['count']}</td></tr>\n"
        html += "</table>\n<h2> Kritik Alert'ler (Level 10+)</h2>\n"
        if analysis["critical_alerts"]:
            html += "<table><tr><th>Timestamp</th><th>Level</th><th>Rule</th><th>Açıklama</th><th>Agent</th></tr>\n"
            for a in analysis["critical_alerts"]:
                html += f"<tr class='level-{a['level']}'><td>{a['timestamp']}</td><td>{a['level']}</td><td>{a['rule_id']}</td><td>{a['description']}</td><td>{a['agent']}</td></tr>\n"
            html += "</table>\n"
        else:
            html += "<p><em>Kritik alert yok.</em></p>\n"
        html += f"""<div class="footer">Otomatik rapor  Wazuh Indexer API<br>
Virtual Enterprise Cybersecurity & SIEM Lab  Phase 4</div></div></body></html>"""
        return html


def main():
    INDEXER_HOST = "https://10.10.10.50:9200"
    INDEXER_USER = "admin"
    INDEXER_PASS = "SecretPassword"
    
    report_dir = os.path.expanduser("~/cybersecurity-lab/phase-04-automation/reports")
    os.makedirs(report_dir, exist_ok=True)
    
    today = datetime.now().strftime("%Y-%m-%d")
    base_path = os.path.join(report_dir, f"daily_{today}")
    
    print(f"[{datetime.now().isoformat()}] Starting daily report generation...")
    
    client = WazuhReportGenerator(INDEXER_HOST, INDEXER_USER, INDEXER_PASS)
    alerts = client.fetch_alerts_last_24h(size=2000)
    print(f"  Fetched: {len(alerts)} alerts (last 24h)")
    
    analysis = client.analyze()
    print(f"  Critical: {len(analysis['critical_alerts'])}")
    
    client.save_json(analysis, f"{base_path}.json")
    client.save_csv(analysis, f"{base_path}.csv")
    client.save_html(analysis, f"{base_path}.html")
    
    print(f"[{datetime.now().isoformat()}] Reports saved to {base_path}.*")
    print(f"[{datetime.now().isoformat()}] Done.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
