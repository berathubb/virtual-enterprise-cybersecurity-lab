#  Virtual Enterprise Cybersecurity & SIEM Lab

Sanal bir kurumsal ağ altyapısı üzerinde geliştirilen, uçtan uca **SIEM, Detection Engineering ve Incident Response** laboratuvarı.

##  Proje Özeti

VMware Workstation üzerinde **pfSense, Windows Server 2019, Windows 10 ve Ubuntu (Wazuh)** makinelerinden oluşan sanal bir kurumsal ağ kuruldu. Active Directory, DNS ve DHCP servisleri yapılandırıldı; pfSense ile firewall ve ağ güvenlik politikaları uygulandı; Windows endpoint **Wazuh Agent** üzerinden merkezi SIEM altyapısına entegre edildi.

##  Amaç

Infrastructure + Cybersecurity + SOC + Automation + Cloud becerilerini **gerçek çalışan bir lab** üzerinden geliştirmek.

##  Mimari

INTERNET


 pfSense 
 Firewall 


LAN 10.10.10.0/24


  
Windows Server Windows 10 Wazuh SIEM
2019 BT-PC01 Ubuntu
10.10.10.100 10.10.10.101 10.10.10.50
AD/DNS/DHCP Wazuh Agent Docker + Wazuh


##  Teknolojiler

| Kategori | Teknoloji |
|----------|-----------|
| **Virtualization** | VMware Workstation |
| **Firewall** | pfSense |
| **Windows** | Server 2019, Windows 10 Pro |
| **Linux** | Ubuntu 24.04 LTS |
| **SIEM** | Wazuh 4.12.0 (Manager + Indexer + Dashboard) |
| **Container** | Docker, Docker Compose |
| **Automation** | Python 3, Bash, Cron |
| **Version Control** | Git, GitHub |

##  Proje Yapısı
virtual-enterprise-cybersecurity-lab/
 phase-01-infrastructure/ # Altyapı kurulumu
 phase-02-detection-engineering/ # Detection kuralları + matrix
 phase-03-incident-response/ # IR senaryoları + raporlar
 phase-04-automation/ # Python + API + Cron
 phase-05-cloud-security/ # AWS (devam ediyor)


##  Tamamlanan Fazlar

### Phase 1  Infrastructure & SIEM Lab
- VMware sanal lab kurulumu
- pfSense firewall + gateway
- Windows Server 2019 (AD, DNS, DHCP)
- Windows 10 endpoint (Wazuh Agent)
- Ubuntu + Docker + Wazuh SIEM
- Firewall kuralları (pfSense + Windows)
- Layer 2 troubleshooting

### Phase 2  SOC & Detection Engineering
- FIM (File Integrity Monitoring)  Rule 554, 550, 553
- Registry FIM  Rule 594, 750
- Failed Login Detection  Rule 60122
- PowerShell Detection  Rule 91837
- Threat Hunting (DQL sorguları)
- SOC Investigation
- **Detection Matrix** (bkz. `phase-02-detection-engineering/`)

### Phase 3  Incident Response
- **IR-2026-09-18-001:** Brute Force Response
- **IR-2026-09-18-002:** FIM Hash Change Response
- **IR-2026-09-18-003:** Malware Persistence Detection
- Sysinternals araç kullanımı (Autoruns, Process Explorer)
- Detection gap analizi
- Profesyonel IR raporlama

### Phase 4  Infrastructure Automation
- Wazuh API keşfi (JWT authentication)
- Python client (REST API + Indexer API)
- Çok formatlı rapor üretimi (JSON, CSV, HTML)
- Cron ile otomatik günlük rapor (her sabah 08:00 UTC)

##  Detection Coverage

| Teknik | MITRE | Rule | Durum |
|--------|-------|------|-------|
| PowerShell Execution | T1059.001 | 91837 |  |
| File Deletion | T1070.004 | 553 |  |
| File Modification | T1565.001 | 550 |  |
| File Addition | T1565.001 | 554 |  |
| Registry Modification | T1112 | 594, 750 |  |
| Failed Login | T1531 | 60122 |  |

##  Backlog

- PowerShell 4104 custom rule (tetiklenmiyor)
- Brute force korelasyon kuralı
- HKCU / HKEY_USERS registry FIM (Wazuh 4.12 kısıtı)
- Nmap port scan detection
- pfSense syslog parsing
- False positive tuning (W32Time gürültüsü)

##  Yol Haritası

- [x] **Phase 1**  Infrastructure & SIEM Lab
- [x] **Phase 2**  SOC & Detection Engineering
- [x] **Phase 3**  Incident Response
- [x] **Phase 4**  Infrastructure Automation
- [ ] **Phase 5**  AWS Cloud Security

##  Lisans

Bu proje eğitim amaçlıdır. Ticari kullanım için değildir.

##  Geliştirici

**Berat**  IT Security Engineer adayı
-  Hedef: Infrastructure + Cybersecurity + Cloud + Automation
-  GitHub: [@berathubb](https://github.com/berathubb)

---

*Bu proje, gerçek bir kurumsal ortamın sanal simülasyonudur. Tüm saldırı senaryoları eğitim amaçlı ve etik sınırlar içindedir.*
