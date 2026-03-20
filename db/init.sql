-- 1. Schema Definition
-- Standard FreeRADIUS tables for AAA (Authentication, Authorization, Accounting)
CREATE TABLE IF NOT EXISTS radcheck (id serial primary key, username varchar(64), attribute varchar(64), op varchar(2), value varchar(253));
CREATE TABLE IF NOT EXISTS radreply (id serial primary key, username varchar(64), attribute varchar(64), op varchar(2), value varchar(253));
CREATE TABLE IF NOT EXISTS radusergroup (id serial primary key, username varchar(64), groupname varchar(64), priority int DEFAULT 1);
CREATE TABLE IF NOT EXISTS radgroupreply (id serial primary key, groupname varchar(64), attribute varchar(64), op varchar(2), value varchar(253));
CREATE TABLE IF NOT EXISTS radacct (
    radacctid bigserial primary key, acctsessionid varchar(64), acctuniqueid varchar(32),
    username varchar(64), groupname varchar(64), nasipaddress inet, nasportid varchar(15),
    acctstatustype varchar(32), acctstarttime timestamp with time zone, acctstoptime timestamp with time zone,
    acctsessiontime bigint, acctauthentic varchar(32), acctinputoctets bigint, acctoutputoctets bigint,
    callingstationid varchar(64) DEFAULT ''
);

-- 2. Performance Optimization
CREATE INDEX idx_radcheck_username ON radcheck (username);
CREATE INDEX idx_radacct_username ON radacct (username);

-- 3. Authentication (Credentials)
-- Secure SHA-512 hashing for user passwords (default: 123456)
INSERT INTO radcheck (username, attribute, op, value) VALUES 
('zeynep', 'Bcrypt-Password', ':=', '$2b$12$h7xCVSu5gg/0AG8GOvoKGu4cKX4KvvSYmSjyH/.db6VKhzjEtFAQi'),
('ahmet', 'Bcrypt-Password', ':=', '$2b$12$h7xCVSu5gg/0AG8GOvoKGu4cKX4KvvSYmSjyH/.db6VKhzjEtFAQi'),
('mehmet', 'Bcrypt-Password', ':=', '$2b$12$h7xCVSu5gg/0AG8GOvoKGu4cKX4KvvSYmSjyH/.db6VKhzjEtFAQi');

-- 4. User-Group Mapping
INSERT INTO radusergroup (username, groupname, priority) VALUES 
('zeynep', 'admin', 1),
('ahmet', 'employee', 1),
('mehmet', 'guest', 1);

-- 5. Authorization Policy (Dynamic VLAN Assignment)
-- Implements project requirement: Group-based network access control
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES 
('admin', 'Tunnel-Type', ':=', 'VLAN'),
('admin', 'Tunnel-Medium-Type', ':=', 'IEEE-802'),
('admin', 'Tunnel-Private-Group-Id', ':=', '10'),
('employee', 'Tunnel-Type', ':=', 'VLAN'),
('employee', 'Tunnel-Medium-Type', ':=', 'IEEE-802'),
('employee', 'Tunnel-Private-Group-Id', ':=', '20'),
('guest', 'Tunnel-Type', ':=', 'VLAN'),
('guest', 'Tunnel-Medium-Type', ':=', 'IEEE-802'),
('guest', 'Tunnel-Private-Group-Id', ':=', '30');

-- MAB (MAC Authentication Bypass) whitelist table
CREATE TABLE IF NOT EXISTS mac_whitelist (
    id          SERIAL PRIMARY KEY,
    mac_address VARCHAR(17) NOT NULL UNIQUE,
    description VARCHAR(128) DEFAULT ''
);

-- Seed data for IoT testing
INSERT INTO mac_whitelist (mac_address, description)
VALUES ('00:11:22:33:44:55', 'Test IoT Device')
ON CONFLICT DO NOTHING;

-- Map IoT device to Guest VLAN (VLAN 30)
INSERT INTO radusergroup (username, groupname, priority)
VALUES ('00:11:22:33:44:55', 'guest', 1)
ON CONFLICT DO NOTHING;