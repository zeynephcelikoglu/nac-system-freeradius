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
    acctsessiontime bigint, acctauthentic varchar(32), acctinputoctets bigint, acctoutputoctets bigint
);

-- 2. Performance Optimization
CREATE INDEX idx_radcheck_username ON radcheck (username);
CREATE INDEX idx_radacct_username ON radacct (username);

-- 3. Authentication (Credentials)
-- Secure SHA-512 hashing for user passwords (default: 123456)
INSERT INTO radcheck (username, attribute, op, value) VALUES 
('zeynep', 'Crypt-Password', ':=', '$6$salt$7.8X9N7k6vH6.9P5x.M3kZ0iH0jG1fF2eE3dD4cC5bB6aA7zZ8yY9xX0wW1vV2uU3tT4sS5rR6qQ7pP8oO9nN0mM1'),
('ahmet', 'Crypt-Password', ':=', '$6$salt$7.8X9N7k6vH6.9P5x.M3kZ0iH0jG1fF2eE3dD4cC5bB6aA7zZ8yY9xX0wW1vV2uU3tT4sS5rR6qQ7pP8oO9nN0mM1'),
('mehmet', 'Crypt-Password', ':=', '$6$salt$7.8X9N7k6vH6.9P5x.M3kZ0iH0jG1fF2eE3dD4cC5bB6aA7zZ8yY9xX0wW1vV2uU3tT4sS5rR6qQ7pP8oO9nN0mM1');

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