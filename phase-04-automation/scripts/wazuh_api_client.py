#!/usr/bin/env python3
"""
Wazuh API Client
Virtual Enterprise Cybersecurity Lab - Phase 4 Automation

Bu script Wazuh API'ye bağlanır ve alert verilerini çeker.
"""

import requests
import json
import urllib3
import sys
from datetime import datetime
from typing import Optional

# Self-signed SSL uyarısını kapat
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhAPIClient:
    """Wazuh Manager API ile iletişim kuran client"""
    
    def __init__(self, host: str, username: str, password: str):
        """
        Args:
            host: Wazuh API URL (örn: https://10.10.10.50:55000)
            username: API kullanıcı adı
            password: API şifresi
        """
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.token: Optional[str] = None
    
    def authenticate(self) -> str:
        """API token al"""
        url = f"{self.host}/security/user/authenticate"
        response = requests.post(
            url,
            auth=(self.username, self.password),
            verify=False,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        
        if data.get('error') != 0:
            raise Exception(f"Auth failed: {data}")
        
        self.token = data['data']['token']
        return self.token
    
    def _headers(self) -> dict:
        """Authorization header'ı döndür"""
        if not self.token:
            raise Exception("Not authenticated. Call authenticate() first.")
        return {"Authorization": f"Bearer {self.token}"}
    
    def get_manager_info(self) -> dict:
        """Manager bilgilerini al"""
        url = f"{self.host}/manager/info"
        response = requests.get(url, headers=self._headers(), verify=False, timeout=10)
        response.raise_for_status()
        return response.json()
    
    def get_agents(self) -> list:
        """Tüm agent'ları listele"""
        url = f"{self.host}/agents"
        response = requests.get(url, headers=self._headers(), verify=False, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data['data']['affected_items']
    
    def get_alerts(self, limit: int = 100) -> list:
        """Son alert'leri çek"""
        url = f"{self.host}/manager/logs?limit={limit}"
        response = requests.get(url, headers=self._headers(), verify=False, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data['data']['affected_items']
    
    def get_agent_summary(self, agent_id: str = None) -> dict:
        """Belirli agent'ın özetini al"""
        url = f"{self.host}/agents/summary/status"
        if agent_id:
            url += f"?agents_list={agent_id}"
        response = requests.get(url, headers=self._headers(), verify=False, timeout=10)
        response.raise_for_status()
        return response.json()


def main():
    """Ana fonksiyon - demo"""
    
    # Config
    API_HOST = "https://10.10.10.50:55000"
    API_USER = "wazuh-wui"
    API_PASS = "MyS3cr37P450r.*-"
    
    print("=" * 60)
    print("Wazuh API Client - Phase 4 Automation")
    print("=" * 60)
    print(f"Time: {datetime.now().isoformat()}")
    print()
    
    # Client oluştur
    client = WazuhAPIClient(API_HOST, API_USER, API_PASS)
    
    # 1. Authenticate
    print("[1] Authenticating...")
    token = client.authenticate()
    print(f"     Token: {token[:40]}...")
    print()
    
    # 2. Manager info
    print("[2] Manager Info:")
    info = client.get_manager_info()
    manager = info['data']['affected_items'][0]
    print(f"    Version : {manager['version']}")
    print(f"    Type    : {manager['type']}")
    print(f"    Timezone: {manager['tz_name']}")
    print()
    
    # 3. Agents
    print("[3] Agents:")
    agents = client.get_agents()
    for agent in agents:
        print(f"    [{agent['id']}] {agent['name']}")
        print(f"          IP    : {agent['ip']}")
        print(f"          OS    : {agent['os']['name']} {agent['os'].get('version', '')}")
        print(f"          Status: {agent['status']}")
    print()
    
    # 4. Alert özeti
    print("[4] Recent Alerts (last 10):")
    alerts = client.get_alerts(limit=10)
    if not alerts:
        print("    (no alerts)")
    else:
        for alert in alerts[:10]:
            timestamp = alert.get('timestamp', 'N/A')[:19]
            desc = alert.get('description', 'N/A')[:60]
            print(f"    {timestamp} | {desc}")
    print()
    
    print("=" * 60)
    print(" Script completed successfully")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n ERROR: {e}", file=sys.stderr)
        sys.exit(1)
