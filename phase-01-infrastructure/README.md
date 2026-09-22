# Phase 1  Infrastructure & SIEM Lab

Bu fazda sanal kurumsal ağ altyapısı kuruldu.

## İçerik

- VMware Workstation sanal lab
- pfSense firewall + gateway (WAN: 192.168.1.9, LAN: 10.10.10.1)
- Windows Server 2019 (10.10.10.100)  AD, DNS, DHCP
- Windows 10 (10.10.10.101)  BT-PC01, Wazuh Agent
- Ubuntu 24.04.4 (10.10.10.50)  Wazuh SIEM (Docker)
- Network: 10.10.10.0/24, VLAN20 (configured)

## Servisler

| Servis | Host | IP |
|--------|------|-----|
| AD/DNS/DHCP | Windows Server 2019 | 10.10.10.100 |
| Firewall | pfSense | 10.10.10.1 |
| Wazuh Manager | Ubuntu (Docker) | 10.10.10.50 |
| Endpoint | Windows 10 | 10.10.10.101 |

## Kazanımlar

- Kurumsal ağ mimarisi
- Firewall kuralları (pfSense + Windows Firewall)
- Layer 2 vs Layer 3 trafik analizi
- Wazuh Agent kurulumu ve entegrasyonu
