#!/usr/bin/env python3
"""
Wazuh Daily Security Report Generator
Virtual Enterprise Cybersecurity Lab - Phase 4.3

Bu script Wazuh Indexer'dan alert çeker ve çok formatlı rapor üretir.
"""

import requests
import json
import csv
import urllib3
import sys
import os
from datetime import datetime
from typing import List, Dict
from collections import Counter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhReportGenerator:
    """Wazuh alert'lerinden rapor üreten sınıf"""
    
    def __init__(self, host: str, username: str, password: str):
        self.host = host.rstrip('/')
        self.auth = (username, password)
        self.alerts: List[Dict] = []
    
    def fetch_alerts(self, size: int = 500) -> List[Dict]:
        """Alert'leri çek"""
        url = f"{self.host}/wazuh-alerts-*/_search"
        params = {"size": size, "sort": "@timestamp:desc"}
        body = {"query": {"match_all": {}}}
        
        response = requests.post(
            url, params=params, json=body,
            auth=self.auth, verify=False, timeout=30
        )
        response.raise_for_status()
        data = response.json()
        
        self.alerts = [hit['_source'] for hit in data['hits']['hits']]
        return self.alerts
    
    def analyze(self) -> Dict:
        """Alert'leri analiz et"""
        analysis = {
            "generated_at": datetime.now().isoformat(),
            "total_alerts": len(self.alerts),
            "by_level": {},
            "by_agent": {},
            "by_rule": {},
            "critical_alerts": [],
            "top_rules": []
        }
        
        level_counter = Counter()
        agent_counter = Counter()
        rule_counter = Counter()
        
        for alert in self.alerts:
            rule = alert.get('rule', {})
            agent = alert.get('agent', {})
            
            # Level dağılımı
            level = rule.get('level', 0)
            level_counter[level] += 1
            
            # Agent dağılımı
            agent_name = agent.get('name', 'unknown')
            agent_counter[agent_name] += 1
            
            # Rule dağılımı
            rule_id = rule.get('id', 'unknown')
            rule_desc = rule.get('description', 'unknown')
            rule_counter[(rule_id, rule_desc)] += 1
            
            # Kritik alert'ler (Level 10+)
            if level >= 10:
                analysis["critical_alerts"].append({
                    "timestamp": alert.get('@timestamp', '')[:19],
                    "level": level,
                    "rule_id": rule_id,
                    "description": rule_desc,
                    "agent": agent_name,
                    "mitre": rule.get('mitre', {}).get('id', [])
                })
        
        # Sırala
        analysis["by_level"] = dict(sorted(level_counter.items()))
        analysis["by_agent"] = dict(agent_counter.most_common())
        analysis["by_rule"] = dict(
            (f"{rid}|{desc[:60]}", count)
            for (rid, desc), count in rule_counter.most_common(20)
        )
        analysis["top_rules"] = [
            {"rule_id": rid, "description": desc[:80], "count": count}
            for (rid, desc), count in rule_counter.most_common(10)
        ]
        
        # Kritik alert'leri sırala (level DESC, timestamp DESC)
        analysis["critical_alerts"].sort(
            key=lambda x: (-x['level'], x['timestamp']),
            reverse=False
        )
        
        return analysis
    
    def save_json(self, analysis: Dict, filepath: str):
        """JSON rapor üret"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
        print(f"     JSON: {filepath}")
    
    def save_csv(self, analysis: Dict, filepath: str):
        """CSV rapor üret (kritik alert'ler)"""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "Timestamp", "Level", "Rule ID", "Description",
                "Agent", "MITRE Technique"
            ])
            for alert in analysis["critical_alerts"]:
                writer.writerow([
                    alert["timestamp"],
                    alert["level"],
                    alert["rule_id"],
                    alert["description"],
                    alert["agent"],
                    ",".join(alert["mitre"]) if alert["mitre"] else "-"
                ])
        print(f"     CSV : {filepath}")
    
    def save_markdown(self, analysis: Dict, filepath: str):
        """Markdown rapor üret"""
        md = []
        md.append(f"# Wazuh Günlük Güvenlik Raporu\n")
        md.append(f"**Rapor Tarihi:** {analysis['generated_at']}\n")
        md.append(f"**Toplam Alert:** {analysis['total_alerts']}\n")
        md.append("---\n")
        
        # Level dağılımı
        md.append("##  Rule Level Dağılımı\n")
        md.append("| Level | Alert Sayısı |")
        md.append("|-------|--------------|")
        for level, count in analysis["by_level"].items():
            md.append(f"| {level} | {count} |")
        md.append("")
        
        # Agent dağılımı
        md.append("##  Agent Dağılımı\n")
        md.append("| Agent | Alert Sayısı |")
        md.append("|-------|--------------|")
        for agent, count in analysis["by_agent"].items():
            md.append(f"| {agent} | {count} |")
        md.append("")
        
        # Top rule'lar
        md.append("##  En Çok Tetiklenen Rule'lar (Top 10)\n")
        md.append("| Rule ID | Açıklama | Sayı |")
        md.append("|---------|----------|------|")
        for rule in analysis["top_rules"]:
            md.append(f"| {rule['rule_id']} | {rule['description'][:50]} | {rule['count']} |")
        md.append("")
        
        # Kritik alert'ler
        md.append("##  Kritik Alert'ler (Level 10+)\n")
        if analysis["critical_alerts"]:
            md.append("| Timestamp | Level | Rule | Açıklama | Agent |")
            md.append("|-----------|-------|------|----------|-------|")
            for alert in analysis["critical_alerts"]:
                md.append(
                    f"| {alert['timestamp']} | **{alert['level']}** | "
                    f"{alert['rule_id']} | {alert['description'][:60]} | "
                    f"{alert['agent']} |"
                )
        else:
            md.append("*Kritik alert bulunamadı.*")
        md.append("")
        
        md.append("---")
        md.append(f"*Rapor otomatik olarak Wazuh Indexer API üzerinden üretilmiştir.*")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(md))
        print(f"     MD  : {filepath}")
    
    def save_html(self, analysis: Dict, filepath: str):
        """HTML rapor üret"""
        html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Wazuh Security Report - {analysis['generated_at'][:10]}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #f5f5f5; margin: 0; padding: 20px; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white;
                     padding: 40px; border-radius: 8px;
                     box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a1a; border-bottom: 3px solid #0066cc; padding-bottom: 10px; }}
        h2 {{ color: #0066cc; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                   gap: 15px; margin: 20px 0; }}
        .card {{ background: #f9f9f9; padding: 20px; border-radius: 6px;
                border-left: 4px solid #0066cc; }}
        .card .number {{ font-size: 32px; font-weight: bold; color: #0066cc; }}
        .card .label {{ color: #666; font-size: 14px; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th {{ background: #0066cc; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #eee; }}
        tr:hover {{ background: #f9f9f9; }}
        .critical {{ background: #ffebee; }}
        .level-13 {{ background: #b71c1c; color: white; font-weight: bold; }}
        .level-12 {{ background: #d32f2f; color: white; font-weight: bold; }}
        .level-10, .level-11 {{ background: #f57c00; color: white; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee;
                  color: #999; font-size: 12px; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1> Wazuh Günlük Güvenlik Raporu</h1>
        <p><strong>Rapor Tarihi:</strong> {analysis['generated_at']}</p>
        
        <div class="summary">
            <div class="card">
                <div class="number">{analysis['total_alerts']}</div>
                <div class="label">Toplam Alert</div>
            </div>
            <div class="card">
                <div class="number">{len(analysis['critical_alerts'])}</div>
                <div class="label">Kritik Alert (L10+)</div>
            </div>
            <div class="card">
                <div class="number">{len(analysis['by_agent'])}</div>
                <div class="label">Aktif Agent</div>
            </div>
            <div class="card">
                <div class="number">{len(analysis['top_rules'])}</div>
                <div class="label">Farklı Rule</div>
            </div>
        </div>
        
        <h2> Rule Level Dağılımı</h2>
        <table>
            <tr><th>Level</th><th>Alert Sayısı</th></tr>
"""
        for level, count in analysis["by_level"].items():
            css = f"level-{level}" if level >= 10 else ""
            html += f"            <tr class='{css}'><td>Level {level}</td><td>{count}</td></tr>\n"
        
        html += """        </table>
        
        <h2> Agent Dağılımı</h2>
        <table>
            <tr><th>Agent</th><th>Alert Sayısı</th></tr>
"""
        for agent, count in analysis["by_agent"].items():
            html += f"            <tr><td>{agent}</td><td>{count}</td></tr>\n"
        
        html += """        </table>
        
        <h2> En Çok Tetiklenen Rule'lar (Top 10)</h2>
        <table>
            <tr><th>Rule ID</th><th>Açıklama</th><th>Sayı</th></tr>
"""
        for rule in analysis["top_rules"]:
            html += f"            <tr><td>{rule['rule_id']}</td><td>{rule['description']}</td><td>{rule['count']}</td></tr>\n"
        
        html += """        </table>
        
        <h2> Kritik Alert'ler (Level 10+)</h2>
"""
        if analysis["critical_alerts"]:
            html += """        <table>
            <tr><th>Timestamp</th><th>Level</th><th>Rule</th><th>Açıklama</th><th>Agent</th></tr>
"""
            for alert in analysis["critical_alerts"]:
                css = f"level-{alert['level']}"
                html += f"""            <tr class='{css}'>
                <td>{alert['timestamp']}</td>
                <td>{alert['level']}</td>
                <td>{alert['rule_id']}</td>
                <td>{alert['description']}</td>
                <td>{alert['agent']}</td>
            </tr>
"""
            html += "        </table>\n"
        else:
            html += "        <p><em>Kritik alert bulunamadı.</em></p>\n"
        
        html += f"""        
        <div class="footer">
            Bu rapor otomatik olarak Wazuh Indexer API üzerinden üretilmiştir.<br>
            Virtual Enterprise Cybersecurity & SIEM Lab  Phase 4 Automation
        </div>
    </div>
</body>
</html>"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"     HTML: {filepath}")


def main():
    """Ana fonksiyon"""
    
    # Config
    INDEXER_HOST = "https://10.10.10.50:9200"
    INDEXER_USER = "admin"
    INDEXER_PASS = "SecretPassword"
    
    # Rapor dizini
    report_dir = os.path.expanduser("~/cybersecurity-lab/phase-04-automation/reports")
    os.makedirs(report_dir, exist_ok=True)
    
    today = datetime.now().strftime("%Y-%m-%d")
    base_path = os.path.join(report_dir, f"report_{today}")
    
    print("=" * 70)
    print("Wazuh Daily Report Generator")
    print("=" * 70)
    print(f"Time: {datetime.now().isoformat()}")
    print(f"Output directory: {report_dir}")
    print()
    
    # 1. Client oluştur
    print("[1] Connecting to Wazuh Indexer...")
    client = WazuhReportGenerator(INDEXER_HOST, INDEXER_USER, INDEXER_PASS)
    print(f"     Connected: {INDEXER_HOST}")
    print()
    
    # 2. Alert'leri çek
    print("[2] Fetching alerts...")
    alerts = client.fetch_alerts(size=500)
    print(f"     Retrieved: {len(alerts)} alerts")
    print()
    
    # 3. Analiz et
    print("[3] Analyzing alerts...")
    analysis = client.analyze()
    print(f"     Analyzed: {analysis['total_alerts']} alerts")
    print(f"     Critical (L10+): {len(analysis['critical_alerts'])}")
    print()
    
    # 4. Raporları üret
    print("[4] Generating reports...")
    client.save_json(analysis, f"{base_path}.json")
    client.save_csv(analysis, f"{base_path}.csv")
    client.save_markdown(analysis, f"{base_path}.md")
    client.save_html(analysis, f"{base_path}.html")
    print()
    
    print("=" * 70)
    print(" All reports generated successfully")
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n ERROR: {e}", file=sys.stderr)
        sys.exit(1)
