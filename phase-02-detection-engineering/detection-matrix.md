



| 9 | Sysmon: Discovery commands (whoami/net/systeminfo) | 100301 | 8 | Sysmon Event 1 | T1033, T1087, T1016 |  |
| 10 | Sysmon: PowerShell Encoded Command | 100302 | 12 | Sysmon Event 1 | T1059.001, T1027 |  |
| 11 | Sysmon: Suspicious PowerShell (IEX/Download/Base64) | 100304 | 10 | Sysmon Event 1 | T1059.001, T1105 |  || **T1033** | System Owner/User Discovery |  (100301) |
| **T1087** | Account Discovery |  (100301) |
| **T1016** | System Network Configuration Discovery |  (100301) |
| **T1059.001** | PowerShell |  (91837, 100302, 100304) |
| **T1027** | Obfuscated Files or Information |  (100302) |
| **T1105** | Ingress Tool Transfer |  (100304) |# Detection Matrix  Virtual Enterprise Cybersecurity Lab

**Proje:** Virtual Enterprise Cybersecurity & SIEM Lab
**Faz:** Phase 2  SOC & Detection Engineering
**Son Güncelleme:** 2026-09-22
**Wazuh Sürüm:** 4.12.0 (Docker single-node)

---

## 1. Çalışan Detection'lar (Verified)

| # | Detection | Rule ID | Level | Log Source | MITRE ATT&CK | Durum |
|---|---|---|---|---|---|---|
| 1 | Failed Login - Unknown user/bad password | 60122 | 5 | Windows Security (4625) | T1531 |  |
| 2 | File Added to System (FIM) | 554 | 5 | Syscheck | T1565.001 |  |
| 3 | File Modified - Integrity Checksum | 550 | 7 | Syscheck | T1565.001 |  |
| 4 | File Deleted | 553 | 7 | Syscheck | T1070.004 |  |
| 5 | Registry Key Modified | 594 | 5 | Syscheck | T1565.001, T1112 |  |
| 6 | Registry Value Modified | 750 | 5 | Syscheck | T1565.001, T1112 |  |
| 7 | PowerShell Suspicious - IEX | 91837 | 4 | Win PS/Operational (4104) | T1059.001 |  |
| 8 | PowerShell Suspicious - Base64/Download | 91838-91845 | 4-14 | Win PS/Operational | T1059.001, T1027 |  |

**Toplam çalışan detection: 8**

---

## 2. Backlog  Tasarlanan ama Çalışmayan

| # | Detection | Rule ID | Hedef Level | Sorun |
|---|---|---|---|---|
| 1 | PowerShell 4104 Custom Base Rule | 100100 | 3 | Tetiklenmiyor |
| 2 | PowerShell Suspicious - IEX (custom) | 100101 | 10 | Tetiklenmiyor |
| 3 | Brute Force - Same User (custom) | 100200 | 10 | Tetiklenmiyor |
| 4 | Brute Force - Same IP (custom) | 100201 | 12 | Tetiklenmiyor |
| 5 | pfSense Syslog Meaningful Alert | - | - | Decoder eksik |
| 6 | Nmap Port Scan Detection | - | - | Log source yok |
| 7 | HKCU Registry FIM | - | - | Wazuh 4.12 kısıtı |
| 8 | W32Time Noise Suppression | - | - | False positive tuning |

---

## 3. MITRE ATT&CK Coverage

| Teknik | İsim | Detection Var mı? |
|---|---|---|
| **T1059.001** | PowerShell |  (91837) |
| **T1070.004** | Indicator Removal: File Deletion |  (553) |
| **T1110** | Brute Force |  (60122 tek login, korelasyon eksik) |
| **T1112** | Modify Registry |  (594, 750) |
| **T1531** | Account Access Removal |  (60122) |
| **T1547.001** | Registry Run Keys Persistence |  (backlog #7) |
| **T1565.001** | Stored Data Manipulation |  (550, 554) |
| **T1046** | Network Service Scanning |  (backlog #6) |

**Kapsanan teknikler: 5  / 1  / 2 **

---

## 4. Compliance Mapping

| Standart | Kapsanan Alan | Detection'lar |
|---|---|---|
| **PCI DSS 10.2.4** | Başarısız erişim denemeleri | 60122 |
| **PCI DSS 10.2.5** | Erişim değiştirme | 60122 |
| **PCI DSS 11.5** | Dosya bütünlüğü izleme | 550, 553, 554, 594, 750 |
| **NIST 800-53 AU.14** | Denetim kaydı | 60122 |
| **NIST 800-53 SI.7** | Yazılım bütünlüğü | 550, 553, 554 |

---

## 5. Özet İstatistikler

| Metrik | Değer |
|---|---|
| Toplam Log Kaynağı | 7 |
| Çalışan Detection | 8 |
| Backlog Detection | 8 |
| MITRE Teknik (kapsanan) | 5 |
| Agent Sayısı | 1 (BT-PC01) |
| Günlük Alert Hacmi | ~500 (çoğu W32Time noise) |

---

*Bu doküman Virtual Enterprise Cybersecurity & SIEM Lab projesinin bir parçasıdır.*
