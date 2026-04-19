# AI Network Guardian

AI destekli, tarayıcı tabanlı ağ tanı paneli. Yerel ağ tarama, URL güvenlik analizi, TCP performans ölçümü ve bağlantı testi özelliklerini tek bir arayüzde birleştirir. Her analiz Google Gemini 2.0 Flash tarafından yorumlanır; API anahtarı yoksa kural tabanlı motor devreye girer.

---

## Özellikler

### Network Detective — L1/L2
Yerel ağdaki cihazları ARP tablosu üzerinden keşfeder.
- Windows/macOS/Linux ARP çıktısını parse eder
- Broadcast, Multicast ve kendi IP adresini otomatik filtreler
- MAC OUI eşleştirmesiyle üretici (vendor) bilgisi çıkarır
- Her cihaza ping atarak bağlantı durumunu doğrular
- Gateway'i otomatik tespit eder

### Security Hunter — L7
URL ve alan adlarının güvenliğini analiz eder.
- SSL/TLS sertifikası doğrulama (geçerlilik, son kullanma tarihi, issuer)
- WHOIS sorgusu ile domain yaşı ve registrar kontrolü
- 0–100 arası risk skoru: **SAFE / CAUTION / DANGEROUS**
- Phishing göstergesi tespiti (şüpheli keyword, derin subdomain, genç domain)
- WHOIS verisi tamamen N/A ise güven skoru otomatik %50'ye düşer

### Performance Monitor — L3/L4
TCP socket bağlantılarıyla ağ performansını ölçer (ICMP ping gerektirmez).
- Min / Avg / Max gecikme, jitter ve paket kaybı
- Port otomatik seçimi (443 → 80 → 53 → 22 → 8080)
- Aktif TCP/UDP bağlantı sayısı ve durum dağılımı
- DNS çözümleme süresi

### Connection Test — L1-L4
Belirtilen IP:Port'a doğrudan TCP bağlantısı dener ve her katmanı raporlar.

| Sonuç | Anlam |
|---|---|
| **CONNECTED** | Port açık, bağlantı kuruldu |
| **REFUSED** | TCP RST alındı, port kapalı |
| **TIMEOUT** | Yanıt yok, muhtemelen firewall |
| **UNREACHABLE** | L3 routing hatası |

---

## Kurulum

### Gereksinimler
- Python 3.9+
- (Opsiyonel) Google Gemini API anahtarı

### Adımlar

```bash
# 1. Repoyu klonla
git clone https://github.com/your-username/ai-network-guardian.git
cd ai-network-guardian

# 2. Sanal ortam oluştur ve aktive et
python -m venv venv

# Windows:
venv\Scripts\activate
# macOS / Linux:
source venv/bin/activate

# 3. Bağımlılıkları yükle
pip install -r requirements.txt

# 4. (Opsiyonel) Gemini API anahtarını ayarla
# .env dosyasını aç ve anahtarını yaz:
echo GEMINI_API_KEY=your_key_here > .env

# 5. Uygulamayı başlat
python app.py
```

Tarayıcıda aç: **http://127.0.0.1:5001**

---

## Kullanım Örnekleri

### Ağ Tarama
1. **Network Detective** sekmesine geç
2. **Scan Network** butonuna tıkla
3. Ağdaki cihazlar, MAC adresleri ve üretici bilgileriyle listelenir
4. AI tanısı unknown cihazları ve güvenlik anomalilerini raporlar

### URL Güvenlik Analizi
1. **Security Hunter** sekmesine geç
2. URL kutusuna adres yaz: `example.com`
3. **Analyze URL** butonuna tıkla
4. SSL sertifikası, domain yaşı ve risk skoru (SAFE / CAUTION / DANGEROUS) görüntülenir

### Performans Testi
1. **Performance Monitor** sekmesine geç
2. Hedef host gir (varsayılan: `8.8.8.8`) ve ping sayısını ayarla
3. **Run Diagnostics** butonuna tıkla
4. Gecikme grafiği, bağlantı durumları ve DNS süresi görüntülenir

### Bağlantı Testi
1. **Connection Test** sekmesine geç
2. IP adresi ve port gir (veya hızlı preset butonlarından seç: HTTP 80, HTTPS 443, SSH 22…)
3. **Test Connection** butonuna tıkla
4. L1–L4 katman analizi ve AI tanısı görüntülenir

---

## Ekran Görüntüleri

> Ekran görüntüleri `screenshots/` klasörüne eklenebilir.

```
screenshots/
├── network-detective.png    # Cihaz listesi ve AI tanısı
├── security-hunter.png      # Risk skoru ve SSL detayları
├── performance-monitor.png  # Gecikme grafiği
└── connection-test.png      # L1-L4 katman analizi
```

---

## Teknolojiler

| Katman | Teknoloji |
|---|---|
| Backend | Python 3.9, Flask 3.1 |
| AI Motoru | Google Gemini 2.0 Flash (REST API) |
| Fallback | Kural tabanlı deterministik motor |
| Ağ Analizi | `socket`, `subprocess` (arp, netstat) |
| Domain/SSL | `python-whois`, `ssl`, `socket` |
| Veritabanı | SQLite (WAL modu) |
| Frontend | Vanilla JS, HTML5, CSS3 |
| Konfigürasyon | `python-dotenv` |

---

## Proje Yapısı

```
ai-network-guardian/
├── app.py                  # Flask uygulama ve API route'ları
├── database.py             # SQLite zaman serisi katmanı
├── requirements.txt
├── .env                    # API anahtarı (git'e eklenmez)
├── ai/
│   └── reasoning.py        # Gemini API + kural tabanlı fallback motoru
├── network/
│   ├── detective.py        # ARP tarama, cihaz keşfi, bağlantı testi
│   ├── security.py         # SSL/TLS, WHOIS, phishing risk analizi
│   └── performance.py      # TCP gecikme ölçümü, netstat, DNS
├── static/
│   ├── css/style.css
│   └── js/app.js
└── templates/
    └── index.html
```

---

## Notlar

- **Gemini API anahtarı olmadan** uygulama çalışır; AI yerine kural tabanlı motor devreye girer. `http://127.0.0.1:5001/api/status` adresinden aktif modu görebilirsin.
- **Network Detective**, ARP tablosunu okur. Cihazların listede görünmesi için aynı alt ağda iletişim kurmuş olmaları gerekir.
- **Performance Monitor**, ICMP ping yerine TCP socket kullandığı için yönetici yetkisi gerektirmez ve güvenlik duvarı tarafından engellenmez.

---

## Geliştirici

**Hamide Sila AKDAN & Bekir Sadik ALTUNKAYA**
