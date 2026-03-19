-- Table for user credentials (PAP/CHAP)
CREATE TABLE IF NOT EXISTS radcheck (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op VARCHAR(2) NOT NULL DEFAULT '==',
    value VARCHAR(253) NOT NULL DEFAULT ''
);
CREATE INDEX idx_radcheck_username ON radcheck (username);

-- Table for specific user reply attributes
CREATE TABLE IF NOT EXISTS radreply (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op VARCHAR(2) NOT NULL DEFAULT '=',
    value VARCHAR(253) NOT NULL DEFAULT ''
);

-- Table for group-based policies (VLAN assignments)
CREATE TABLE IF NOT EXISTS radgroupreply (
    id SERIAL PRIMARY KEY,
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op VARCHAR(2) NOT NULL DEFAULT '=',
    value VARCHAR(253) NOT NULL DEFAULT ''
);

-- Table for user-group mapping
CREATE TABLE IF NOT EXISTS radusergroup (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    priority INT NOT NULL DEFAULT 1
);

-- Table for RADIUS accounting records
CREATE TABLE IF NOT EXISTS radacct (
    radacctid BIGSERIAL PRIMARY KEY,
    acctsessionid VARCHAR(64) NOT NULL DEFAULT '',
    acctuniqueid VARCHAR(32) NOT NULL DEFAULT '',
    username VARCHAR(64) NOT NULL DEFAULT '',
    nasipaddress inet NOT NULL,
    nasportid VARCHAR(32) DEFAULT NULL,
    acctstarttime TIMESTAMP WITH TIME ZONE,
    acctupdatetime TIMESTAMP WITH TIME ZONE,
    acctstoptime TIMESTAMP WITH TIME ZONE,
    acctsessiontime BIGINT DEFAULT NULL,
    acctinputoctets BIGINT DEFAULT NULL,
    acctoutputoctets BIGINT DEFAULT NULL,
    callingstationid VARCHAR(50) NOT NULL DEFAULT ''
);
CREATE INDEX idx_radacct_sessionid ON radacct (acctsessionid);
CREATE INDEX idx_radacct_username ON radacct (username);

-- Initial test data for development
INSERT INTO radcheck (username, attribute, op, value) VALUES ('zeynep', 'Cleartext-Password', ':=', '123456');

-- Admin group VLAN 10 assignment
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES ('admin', 'Tunnel-Type', ':=', 'VLAN');
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES ('admin', 'Tunnel-Medium-Type', ':=', 'IEEE-802');
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES ('admin', 'Tunnel-Private-Group-Id', ':=', '10');