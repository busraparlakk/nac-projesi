# NAC Sistemi — Network Access Control

S3M Security staj değerlendirme projesi. RADIUS protokolü üzerine kurulu, Docker ile orkestre edilen tam işlevsel bir AAA (Authentication, Authorization, Accounting) altyapısı.

## Teknolojiler

| Servis | Teknoloji | Açıklama |
|--------|-----------|----------|
| RADIUS Sunucusu | FreeRADIUS 3.2 | Auth, authz, acct |
| Policy Engine | Python 3.12 + FastAPI | REST tabanlı karar motoru |
| Veritabanı | PostgreSQL 16 | Kullanıcı, grup, accounting |
| Önbellek | Redis 7 | Oturum cache, rate-limiting |
| Orkestrasyon | Docker Compose | Tek komutla ayağa kalkar |

## Hızlı Başlangıç

### Gereksinimler

- Docker Desktop (WSL 2 entegrasyonu açık)
- Git

### Kurulum

```bash
# Repoyu klonla
git clone https://github.com/KULLANICI_ADIN/nac-projesi.git
cd nac-projesi

# .env dosyasını oluştur
cp .env.example .env

# Sistemi ayağa kaldır
docker compose up -d

# Servislerin sağlıklı olduğunu kontrol et (30 saniye bekle)
docker compose ps
```

Tüm servisler `healthy` durumuna geçtikten sonra sistem kullanıma hazır.

## Servis Adresleri

| Servis | Adres |
|--------|-------|
| FastAPI (Swagger UI) | http://localhost:8000/docs |
| RADIUS Auth | UDP localhost:1812 |
| RADIUS Acct | UDP localhost:1813 |

## Test

### PAP Authentication

```bash
# Başarılı giriş
docker exec nac_freeradius radtest employee_user Employee1234! localhost 0 testing123

# Admin kullanıcı
docker exec nac_freeradius radtest admin_user Admin1234! localhost 0 testing123

# Misafir kullanıcı
docker exec nac_freeradius radtest guest_user Guest1234! localhost 0 testing123

# Yanlış şifre (Access-Reject beklenir)
docker exec nac_freeradius radtest employee_user YANLIS_SIFRE localhost 0 testing123
```

### MAC Authentication Bypass (MAB)

```bash
# Bilinen MAC — Access-Accept beklenir
echo "User-Name=aa:bb:cc:dd:ee:ff,User-Password=aa:bb:cc:dd:ee:ff,Calling-Station-Id=aa:bb:cc:dd:ee:ff" | \
  docker exec -i nac_freeradius radclient localhost auth testing123

# Bilinmeyen MAC — Access-Reject beklenir
echo "User-Name=00:00:00:00:00:00,User-Password=00:00:00:00:00:00,Calling-Station-Id=00:00:00:00:00:00" | \
  docker exec -i nac_freeradius radclient localhost auth testing123
```

### Accounting

```bash
# Oturum başlat
echo "User-Name=employee_user,Acct-Status-Type=Start,Acct-Session-Id=test-001,NAS-IP-Address=192.168.1.1,Acct-Input-Octets=0,Acct-Output-Octets=0" | \
  docker exec -i nac_freeradius radclient localhost acct testing123

# Oturum sonlandır
echo "User-Name=employee_user,Acct-Status-Type=Stop,Acct-Session-Id=test-001,NAS-IP-Address=192.168.1.1,Acct-Input-Octets=1024,Acct-Output-Octets=2048,Acct-Session-Time=120,Acct-Terminate-Cause=User-Request" | \
  docker exec -i nac_freeradius radclient localhost acct testing123
```

### FastAPI Endpoint Testleri

```bash
# Sağlık kontrolü
curl http://localhost:8000/health

# Kullanıcı listesi
curl http://localhost:8000/users

# Aktif oturumlar (Redis'ten)
curl http://localhost:8000/sessions/active

# Yeni kullanıcı oluştur
curl -X POST http://localhost:8000/users/create \
  -H "Content-Type: application/json" \
  -d '{"username":"yeni_kullanici","password":"Sifre1234!","groupname":"employee"}'
```

## Varsayılan Kullanıcılar

| Kullanıcı | Şifre | Grup | VLAN |
|-----------|-------|------|------|
| admin_user | Admin1234! | admin | 10 |
| employee_user | Employee1234! | employee | 20 |
| guest_user | Guest1234! | guest | 30 |

## Varsayılan MAC Adresleri

| MAC Adresi | Açıklama | VLAN |
|------------|----------|------|
| aa:bb:cc:dd:ee:ff | Test Yazıcı | 40 |
| 11:22:33:44:55:66 | Test IP Telefon | 40 |

## Proje Yapısı

```
nac-projesi/
├── docker-compose.yml
├── .env.example
├── postgres/
│   └── init.sql              # Veritabanı şeması ve başlangıç verileri
├── freeradius/
│   ├── Dockerfile
│   └── config/
│       ├── radiusd.conf      # Ana konfigürasyon
│       ├── clients.conf      # NAS client tanımları
│       ├── mods-available/
│       │   ├── sql           # PostgreSQL modül konfigürasyonu
│       │   └── rest          # FastAPI entegrasyon konfigürasyonu
│       ├── mods-enabled/     # Aktif modüller
│       └── sites-enabled/
│           └── nac           # Ana sanal sunucu — AAA akışı
└── api/
    ├── Dockerfile
    ├── requirements.txt
    └── app/
        └── main.py           # FastAPI uygulaması
```

## Sistemi Durdurma

```bash
docker compose down
```

Veritabanı verilerini de temizlemek için:

```bash
docker compose down -v
```

## Ortam Değişkenleri

`.env.example` dosyasını kopyalayıp düzenle:

| Değişken | Açıklama |
|----------|----------|
| POSTGRES_DB | Veritabanı adı |
| POSTGRES_USER | Veritabanı kullanıcısı |
| POSTGRES_PASSWORD | Veritabanı şifresi |
| RADIUS_SECRET | RADIUS shared secret |
| DATABASE_URL | PostgreSQL bağlantı URL'i |
| REDIS_URL | Redis bağlantı URL'i |