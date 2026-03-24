-- Kullanıcı kimlik bilgileri (PAP/CHAP)
CREATE TABLE IF NOT EXISTS radcheck (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    attribute VARCHAR(64) NOT NULL,
    op CHAR(2) NOT NULL DEFAULT ':=',
    value VARCHAR(253) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Kullanıcıya dönülecek atribütler
CREATE TABLE IF NOT EXISTS radreply (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    attribute VARCHAR(64) NOT NULL,
    op CHAR(2) NOT NULL DEFAULT ':=',
    value VARCHAR(253) NOT NULL
);

-- Kullanıcı-grup ilişkileri
CREATE TABLE IF NOT EXISTS radusergroup (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    groupname VARCHAR(64) NOT NULL,
    priority INT DEFAULT 1
);

-- Grup bazlı atribütler (VLAN vb.)
CREATE TABLE IF NOT EXISTS radgroupreply (
    id SERIAL PRIMARY KEY,
    groupname VARCHAR(64) NOT NULL,
    attribute VARCHAR(64) NOT NULL,
    op CHAR(2) NOT NULL DEFAULT ':=',
    value VARCHAR(253) NOT NULL
);

-- Accounting kayıtları
CREATE TABLE IF NOT EXISTS radacct (
    radacctid BIGSERIAL PRIMARY KEY,
    acctsessionid VARCHAR(64) NOT NULL,
    acctuniqueid VARCHAR(32),
    username VARCHAR(64),
    nas_ip_address INET,
    nas_port_id VARCHAR(15),
    nas_port_type VARCHAR(32),
    acctstarttime TIMESTAMP,
    acctupdatetime TIMESTAMP,
    acctstoptime TIMESTAMP,
    acctinterval INT,
    acctsessiontime INT,
    acctauthentic VARCHAR(32),
    connectinfo_start VARCHAR(50),
    connectinfo_stop VARCHAR(50),
    acctinputoctets BIGINT DEFAULT 0,
    acctoutputoctets BIGINT DEFAULT 0,
    calledstationid VARCHAR(50),
    callingstationid VARCHAR(50),
    acctterminatecause VARCHAR(32),
    servicetype VARCHAR(32),
    framedprotocol VARCHAR(32),
    framedipaddress INET,
    acctstatustype VARCHAR(32)
);

-- MAB için MAC adresi tablosu
CREATE TABLE IF NOT EXISTS mac_whitelist (
    id SERIAL PRIMARY KEY,
    mac_address VARCHAR(17) UNIQUE NOT NULL,
    description VARCHAR(255),
    groupname VARCHAR(64) DEFAULT 'mac_devices',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Index'ler
CREATE INDEX IF NOT EXISTS idx_radcheck_username ON radcheck(username);
CREATE INDEX IF NOT EXISTS idx_radreply_username ON radreply(username);
CREATE INDEX IF NOT EXISTS idx_radusergroup_username ON radusergroup(username);
CREATE INDEX IF NOT EXISTS idx_radacct_username ON radacct(username);
CREATE INDEX IF NOT EXISTS idx_radacct_session ON radacct(acctsessionid);
CREATE INDEX IF NOT EXISTS idx_mac_whitelist_mac ON mac_whitelist(mac_address);

-- VLAN grup politikaları
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
('admin',    'Tunnel-Type',             ':=', '13'),
('admin',    'Tunnel-Medium-Type',      ':=', '6'),
('admin',    'Tunnel-Private-Group-Id', ':=', '10'),
('employee', 'Tunnel-Type',             ':=', '13'),
('employee', 'Tunnel-Medium-Type',      ':=', '6'),
('employee', 'Tunnel-Private-Group-Id', ':=', '20'),
('guest',    'Tunnel-Type',             ':=', '13'),
('guest',    'Tunnel-Medium-Type',      ':=', '6'),
('guest',    'Tunnel-Private-Group-Id', ':=', '30'),
('mac_devices', 'Tunnel-Type',             ':=', '13'),
('mac_devices', 'Tunnel-Medium-Type',      ':=', '6'),
('mac_devices', 'Tunnel-Private-Group-Id', ':=', '40')
ON CONFLICT DO NOTHING;

-- Test kullanıcıları (şifreler hash'lenmiş — FastAPI /users/seed endpoint'i ile eklenecek)
-- Şimdilik plaintext olarak ekliyoruz, API ayağa kalkınca hash'lenmiş versiyonla güncellenecek
INSERT INTO radcheck (username, attribute, op, value) VALUES
('admin_user',    'Cleartext-Password', ':=', 'Admin1234!'),
('employee_user', 'Cleartext-Password', ':=', 'Employee1234!'),
('guest_user',    'Cleartext-Password', ':=', 'Guest1234!')
ON CONFLICT DO NOTHING;

INSERT INTO radusergroup (username, groupname, priority) VALUES
('admin_user',    'admin',    1),
('employee_user', 'employee', 1),
('guest_user',    'guest',    1)
ON CONFLICT DO NOTHING;

-- Test MAC adresleri
INSERT INTO mac_whitelist (mac_address, description, groupname) VALUES
('aa:bb:cc:dd:ee:ff', 'Test Yazici',   'mac_devices'),
('11:22:33:44:55:66', 'Test IP Telefon', 'mac_devices')
ON CONFLICT DO NOTHING;