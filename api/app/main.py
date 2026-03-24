from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
import asyncpg
import redis.asyncio as aioredis
import os
import json
import time
import bcrypt as _bcrypt
from datetime import datetime

app = FastAPI(title="NAC Policy Engine", version="1.0.0")


# --- Ayarlar ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://radius:radius_secret@postgres:5432/radius")
REDIS_URL    = os.getenv("REDIS_URL", "redis://redis:6379/0")

# --- DB ve Redis bağlantı havuzları ---
db_pool: asyncpg.Pool = None
redis_client = None

@app.on_event("startup")
async def startup():
    global db_pool, redis_client
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True)

@app.on_event("shutdown")
async def shutdown():
    await db_pool.close()
    await redis_client.close()

# ──────────────────────────────────────────
# MODELLER
# ──────────────────────────────────────────

class AuthRequest(BaseModel):
    username: str
    password: str
    nas_ip: Optional[str] = None

class AuthorizeRequest(BaseModel):
    username: str
    nas_ip: Optional[str] = None

class AccountingRequest(BaseModel):
    status_type: str          # Start | Interim-Update | Stop
    session_id: str
    username: str
    nas_ip: Optional[str] = None
    nas_port: Optional[str] = None
    session_time: Optional[int] = 0
    input_octets: Optional[int] = 0
    output_octets: Optional[int] = 0
    calling_station_id: Optional[str] = None
    called_station_id: Optional[str] = None
    terminate_cause: Optional[str] = None

class UserCreate(BaseModel):
    username: str
    password: str
    groupname: str  # admin | employee | guest

# ──────────────────────────────────────────
# YARDIMCI FONKSİYONLAR
# ──────────────────────────────────────────

async def get_user(username: str):
    """Kullanıcıyı ve şifresini DB'den çeker."""
    async with db_pool.acquire() as conn:
        return await conn.fetchrow(
            "SELECT * FROM radcheck WHERE username=$1 AND attribute='Cleartext-Password'",
            username
        )

async def get_user_group(username: str):
    """Kullanıcının grubunu döner."""
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT groupname FROM radusergroup WHERE username=$1 ORDER BY priority LIMIT 1",
            username
        )
        return row["groupname"] if row else None

async def get_group_vlan(groupname: str):
    """Gruba ait VLAN atribütlerini döner."""
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT attribute, value FROM radgroupreply WHERE groupname=$1",
            groupname
        )
        return {r["attribute"]: r["value"] for r in rows}

async def check_rate_limit(username: str) -> bool:
    """
    Redis ile rate limiting:
    5 dakika içinde 5 başarısız denemede hesabı kilitler.
    True  → giriş yapılabilir
    False → kilitli
    """
    key = f"failed_attempts:{username}"
    attempts = await redis_client.get(key)
    if attempts and int(attempts) >= 5:
        return False
    return True

async def record_failed_attempt(username: str):
    """Başarısız girişi Redis'e yazar, 5 dakika TTL."""
    key = f"failed_attempts:{username}"
    await redis_client.incr(key)
    await redis_client.expire(key, 300)  # 5 dakika

async def clear_failed_attempts(username: str):
    """Başarılı girişte sayacı sıfırlar."""
    await redis_client.delete(f"failed_attempts:{username}")

# ──────────────────────────────────────────
# ENDPOINTLER
# ──────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/auth")
async def authenticate(req: AuthRequest):
    """
    PAP/CHAP authentication.
    FreeRADIUS rlm_rest bu endpoint'i çağırır.
    """
    # Rate limit kontrolü
    if not await check_rate_limit(req.username):
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in 5 minutes.")

    user = await get_user(req.username)
    if not user:
        await record_failed_attempt(req.username)
        raise HTTPException(status_code=401, detail="User not found")

    # Şifre doğrulama (bcrypt veya plaintext fallback)
    stored = user["value"]
    if stored.startswith("$2b$"):
        valid = _bcrypt.checkpw(req.password.encode(), stored.encode())
    else:
        valid = (req.password == stored)  # init.sql'deki test kullanıcıları için

    if not valid:
        await record_failed_attempt(req.username)
        raise HTTPException(status_code=401, detail="Invalid password")

    await clear_failed_attempts(req.username)
    return {"code": 2, "reply": {"Reply-Message": "Welcome!"}}


@app.post("/authorize")
async def authorize(req: AuthorizeRequest):
    """
    Kullanıcının grubuna göre VLAN attribute'larını döndürür.
    Eğer kullanıcı adı MAC adresi formatındaysa istek MAB (MAC Authentication Bypass)
    olarak işlenir.
    """
    import re

    # MAC adresi regex deseni (aa:bb:cc:dd:ee:ff veya aa-bb-cc-dd-ee-ff)
    mac_pattern = re.compile(
        r'^([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}$',
        re.IGNORECASE
    )

    # --- MAB akışı ---
    if mac_pattern.match(req.username):
        mac_normalized = req.username.lower()

        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT *
                FROM mac_whitelist
                WHERE mac_address = $1 AND is_active = TRUE
                """,
                mac_normalized
            )

        if not row:
            raise HTTPException(
                status_code=401,
                detail="MAC not authorized"
            )

        vlan_attrs = await get_group_vlan(row["groupname"])

        return {
            "code": 2,
            "reply": vlan_attrs,
            "group": row["groupname"],
        }

    # --- Normal kullanıcı akışı ---
    groupname = await get_user_group(req.username)

    if not groupname:
        raise HTTPException(
            status_code=404,
            detail="User group not found"
        )

    vlan_attrs = await get_group_vlan(groupname)

    return {
        "code": 2,
        "reply": vlan_attrs,
        "group": groupname,
    }


@app.post("/accounting")
async def accounting(req: AccountingRequest):
    """
    Accounting-Start / Interim-Update / Stop paketlerini işler.
    Aktif oturumlar Redis'te cache'lenir.
    """
    now = datetime.utcnow()

    async with db_pool.acquire() as conn:
        if req.status_type == "Start":
            await conn.execute("""
                INSERT INTO radacct
                    (acctsessionid, username, nas_ip_address, nas_port_id,
                     acctstarttime, acctstatustype, callingstationid, calledstationid)
                VALUES ($1,$2,$3,$4,$5,'Start',$6,$7)
                ON CONFLICT DO NOTHING
            """, req.session_id, req.username, req.nas_ip,
                req.nas_port, now, req.calling_station_id, req.called_station_id)

            # Redis'e aktif oturum ekle
            session_data = {
                "username": req.username,
                "nas_ip": req.nas_ip,
                "start_time": now.isoformat(),
                "session_id": req.session_id
            }
            await redis_client.setex(
                f"session:{req.session_id}",
                86400,  # 24 saat TTL
                json.dumps(session_data)
            )
            await redis_client.sadd("active_sessions", req.session_id)

        elif req.status_type == "Interim-Update":
            await conn.execute("""
                UPDATE radacct SET
                    acctupdatetime=$1,
                    acctsessiontime=$2,
                    acctinputoctets=$3,
                    acctoutputoctets=$4,
                    acctstatustype='Interim-Update'
                WHERE acctsessionid=$5
            """, now, req.session_time, req.input_octets,
                req.output_octets, req.session_id)

        elif req.status_type == "Stop":
            await conn.execute("""
                UPDATE radacct SET
                    acctstoptime=$1,
                    acctsessiontime=$2,
                    acctinputoctets=$3,
                    acctoutputoctets=$4,
                    acctterminatecause=$5,
                    acctstatustype='Stop'
                WHERE acctsessionid=$6
            """, now, req.session_time, req.input_octets,
                req.output_octets, req.terminate_cause, req.session_id)

            # Redis'ten oturumu kaldır
            await redis_client.delete(f"session:{req.session_id}")
            await redis_client.srem("active_sessions", req.session_id)

    return {"status": "ok"}


@app.get("/users")
async def list_users():
    """Tüm kullanıcıları grup bilgisiyle listeler."""
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT r.username, r.attribute, ug.groupname, r.created_at
            FROM radcheck r
            LEFT JOIN radusergroup ug ON r.username = ug.username
            WHERE r.attribute = 'Cleartext-Password'
            ORDER BY r.username
        """)
    return [dict(r) for r in rows]


@app.get("/sessions/active")
async def active_sessions():
    """Redis'teki aktif oturumları döner."""
    session_ids = await redis_client.smembers("active_sessions")
    sessions = []
    for sid in session_ids:
        data = await redis_client.get(f"session:{sid}")
        if data:
            sessions.append(json.loads(data))
    return {"count": len(sessions), "sessions": sessions}


@app.post("/users/create")
async def create_user(req: UserCreate):
    """
    Yeni kullanıcı ekler (şifre bcrypt ile hash'lenir).
    """
    hashed = _bcrypt.hashpw(req.password.encode(), _bcrypt.gensalt()).decode()
    async with db_pool.acquire() as conn:
        exists = await conn.fetchrow(
            "SELECT id FROM radcheck WHERE username=$1", req.username
        )
        if exists:
            raise HTTPException(status_code=409, detail="User already exists")

        await conn.execute(
            "INSERT INTO radcheck (username, attribute, op, value) VALUES ($1,'Cleartext-Password',':=',$2)",
            req.username, hashed
        )
        await conn.execute(
            "INSERT INTO radusergroup (username, groupname) VALUES ($1,$2)",
            req.username, req.groupname
        )
    return {"status": "created", "username": req.username, "group": req.groupname}


@app.post("/mab/check")
async def mab_check(mac: str):
    """
    MAC Authentication Bypass:
    MAC adresinin whitelist'te olup olmadığını kontrol eder.
    """
    mac_normalized = mac.lower().replace("-", ":").replace(".", ":")
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM mac_whitelist WHERE mac_address=$1 AND is_active=TRUE",
            mac_normalized
        )
    if not row:
        raise HTTPException(status_code=401, detail="MAC not authorized")

    vlan_attrs = await get_group_vlan(row["groupname"])
    return {
        "code": 2,
        "mac": mac_normalized,
        "group": row["groupname"],
        "reply": vlan_attrs
    }