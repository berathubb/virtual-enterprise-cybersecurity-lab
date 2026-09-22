# Incident Report  IR-2026-09-18-001

## Brute Force Attack Response

| Alan | Değer |
|------|-------|
| **Rapor No** | IR-2026-09-18-001 |
| **Olay Tarihi** | 18 Eylül 2026, 06:43:21 - 06:43:48 UTC |
| **Rapor Tarihi** | 18 Eylül 2026 |
| **Raporlayan** | SOC Analyst (Berat) |
| **Durum** | KAPATILDI (Yetkili Test - False Positive) |
| **Öncelik** | P3 (Düşük-Orta) |

---

## 1. Yönetici Özeti

18 Eylül 2026 sabahı 06:43'te, **BT-PC01** (Windows 10) makinesi üzerinde **administrator@berat.com** hesabına 27 saniye içinde **8 başarısız login denemesi** tespit edildi.

Wazuh SIEM tarafından **Rule 60122** (level 5) ile otomatik olarak algılanan bu aktivite, brute force saldırısı paternine uymaktadır. Ancak yapılan incelemede:

- Kaynak IP'nin `::1` (localhost) olduğu
- Başarılı bir login gerçekleşmediği
- Aktivitenin yetkili bir güvenlik testinden kaynaklandığı

tespit edilmiştir. Olay, **"False Positive / Yetkili Test"** olarak sınıflandırılmış ve kapatılmıştır.

---

## 2. Zaman Çizelgesi

| Zaman (UTC) | Olay |
|-------------|------|
| 06:41:07 | Kullanıcı yönetici PowerShell oturumu açtı (UAC onayı) |
| 06:41:08 | Windows Administrator hesabı ile oturum doğrulaması |
| 06:43:21 | İlk başarısız login denemesi (60122 alert) |
| 06:43:24 | İkinci deneme |
| 06:43:27 | Üçüncü deneme |
| 06:43:33 | Dördüncü deneme |
| 06:43:36 | Beşinci deneme |
| 06:43:42 | Altıncı deneme |
| 06:43:45 | Yedinci deneme |
| 06:43:48 | Sekizinci ve son deneme |
| 06:46:17 | SOC analisti Dashboard'da alert'leri gördü |
| 06:50:00 | Triage tamamlandı: False Positive kararı |
| 06:55:00 | Rapor yazıldı, olay kapatıldı |

**Özet:**
- Toplam saldırı süresi: **27 saniye**
- Toplam başarısız deneme: **8**
- Ortalama deneme aralığı: **~3.4 saniye**

---

## 3. Teknik Detaylar

### 3.1 Etkilenen Varlıklar

| Alan | Değer |
|------|-------|
| Hostname | BT-PC01 |
| IP Adresi | 10.10.10.101 |
| OS | Windows 10 Pro |
| Rol | BT kullanıcı iş istasyonu |
| Domain | berat.com |
| Wazuh Agent ID | 001 |

### 3.2 Hedef Hesap

| Alan | Değer |
|------|-------|
| Kullanıcı Adı | administrator@berat.com |
| Domain | BERAT |
| Hesap Tipi | Domain Administrator |
| Kritiklik | **YÜKSEK** (privileged account) |

### 3.3 Kaynak

| Alan | Değer |
|------|-------|
| Kaynak IP | `::1` (IPv6 localhost) |
| Kaynak Port | 0 (dinamik atanmamış) |
| Workstation | BT-PC01 |
| Process | `C:\Windows\System32\svchost.exe` |
| Process ID | 0x404 |
| Logon Process | seclogo |

### 3.4 Algılama

| Alan | Değer |
|------|-------|
| SIEM | Wazuh 4.12.0 |
| Rule ID | 60122 |
| Rule Level | 5 (Orta) |
| Event ID | 4625 (Windows Security Log) |
| MITRE ATT&CK | T1531 (Account Access Removal) |
| Compliance | PCI DSS 10.2.4, 10.2.5 |

### 3.5 SubStatus Kodu


---

## 4. Analiz

### 4.1 Brute Force Göstergeleri

| Gösterge | Sonuç |
|----------|-------|
| Aynı kullanıcıya tekrarlanan deneme |  EVET (8 kez) |
| Kısa zaman aralığı |  EVET (27 sn) |
| Otomatik script paterni |  EVET (3 sn aralık) |
| Yetkili hesap hedefi |  EVET (administrator) |
| Farklı kaynak IP'ler |  HAYIR (tek IP) |
| Başarılı login |  HAYIR |
| Harici kaynak |  HAYIR (localhost) |

### 4.2 Değerlendirme

Olay teknik olarak brute force paternine uymaktadır. Ancak:

1. Kaynak IP `::1` (localhost)  harici tehdit değil
2. Saldırı öncesi (06:41:08) Administrator hesabıyla başarılı oturum
3. `subStatus 0xc0000064`  geçersiz kimlik bilgileri
4. Deneme hızı 3 saniye/sn  otomatik test script'i
5. Saldırı sonrası hesapta şüpheli aktivite yok

**Karar:** False Positive / Yetkili Test

---

## 5. Yapılan Aksiyonlar

### 5.1 Triage
- Dashboard'da alert'ler incelendi
- Toplam deneme sayısı: 8
- Kaynak IP doğrulandı: `::1`
- Başarılı login kontrolü: Yok
- Şüphe seviyesi: ORTA

### 5.2 Müdahale
- Kullanıcı doğrulaması yapıldı (yetkili test)
- Hesap kilitlenmedi (başarılı login yok)
- IP bloklanmadı (localhost)

### 5.3 Kanıt Toplama (IOC'ler)

| IOC | Değer |
|-----|-------|
| Kullanıcı | administrator@berat.com |
| Kaynak IP | `::1` |
| Process | svchost.exe (PID 0x404) |
| Zaman | 18 Eyl 2026, 06:43:21-48 UTC |
| Event ID | 4625 |
| subStatus | 0xc0000064 |

---

## 6. Sonuç ve Öneriler

### 6.1 Olay Sonucu

| Alan | Değer |
|------|-------|
| Sınıflandırma | False Positive / Yetkili Test |
| Etki | Yok |
| Veri Kaybı | Yok |
| Sistem Durumu | Normal |

### 6.2 Önleyici Tedbirler

- [ ] Hesap kilitleme politikası gözden geçirilmeli (Account Lockout Threshold: 10 deneme / 15 dk)
- [ ] Windows Security log'unda 4625 için ek filtre (test kullanıcıları hariç)
- [ ] MFA (Multi-Factor Authentication) değerlendirilmeli

### 6.3 İyileştirme Önerileri

- [ ] Brute force detection korelasyon kuralı (backlog #4) tamamlanmalı
- [ ] Alert önceliklendirme sistemi (localhost kaynaklı: P4, dış IP: P1)
- [ ] Otomatik yanıt (SOAR) entegrasyonu

### 6.4 Ders Çıkarılanlar

1. Localhost (`::1`) kaynaklı alert'ler düşük öncelikli değerlendirilmeli
2. Test aktivitelerinin önceden SOC'a bildirilmesi gerekir
3. 60122 kuralı hassas ama gürültülü olabilir  tuning gerekli
4. Başarılı login kontrolü (4624) triage'ın ilk adımı olmalı

---

**Rapor Sonu**

*İmza: SOC Analyst  Berat*
*Tarih: 18 Eylül 2026*
