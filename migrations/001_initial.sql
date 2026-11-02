CREATE TABLE IF NOT EXISTS schema_versions (
 version INT PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 username VARCHAR(32) NOT NULL UNIQUE,
 display_name VARCHAR(120) NOT NULL,
 password_hash VARCHAR(255) NOT NULL,
 role ENUM('admin','user') NOT NULL DEFAULT 'user',
 enabled BOOLEAN NOT NULL DEFAULT TRUE,
 session_version INT NOT NULL DEFAULT 1,
 system_synced BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS login_attempts (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 ip_hash CHAR(64) NOT NULL,
 username_hash CHAR(64) NOT NULL,
 attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 INDEX by_ip (ip_hash, attempted_at), INDEX by_name (username_hash, attempted_at)
);
CREATE TABLE IF NOT EXISTS settings (
 name VARCHAR(64) PRIMARY KEY, value LONGTEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS volumes (
 uuid VARCHAR(128) PRIMARY KEY, persistent BOOLEAN NOT NULL DEFAULT FALSE,
 last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS directories (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 volume_uuid VARCHAR(128) NOT NULL, name VARCHAR(80) NOT NULL,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 UNIQUE KEY volume_name(volume_uuid, name)
);
CREATE TABLE IF NOT EXISTS directory_access (
 directory_id BIGINT UNSIGNED NOT NULL,
 user_id BIGINT UNSIGNED NOT NULL,
 mode ENUM('ro','rw') NOT NULL,
 PRIMARY KEY(directory_id,user_id),
 FOREIGN KEY(directory_id) REFERENCES directories(id),
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS shares (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 directory_id BIGINT UNSIGNED NOT NULL UNIQUE,
 name VARCHAR(64) NOT NULL UNIQUE,
 enabled BOOLEAN NOT NULL DEFAULT TRUE,
 FOREIGN KEY(directory_id) REFERENCES directories(id)
);
CREATE TABLE IF NOT EXISTS backups (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 name VARCHAR(80) NOT NULL,
 source_id BIGINT UNSIGNED NOT NULL,
 destination_uuid VARCHAR(128) NOT NULL,
 destination_name VARCHAR(80) NOT NULL,
 schedule ENUM('manual','hourly','daily','weekly') NOT NULL DEFAULT 'daily',
 retention INT NOT NULL DEFAULT 7,
 enabled BOOLEAN NOT NULL DEFAULT TRUE,
 owner_id BIGINT UNSIGNED NULL,
 allow_owner_view BOOLEAN NOT NULL DEFAULT FALSE,
 FOREIGN KEY(source_id) REFERENCES directories(id),
 FOREIGN KEY(owner_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS jobs (
 id CHAR(32) PRIMARY KEY,
 actor_id BIGINT UNSIGNED NULL,
 operation VARCHAR(64) NOT NULL,
 params LONGTEXT NOT NULL,
 status ENUM('queued','running','completed','failed') NOT NULL DEFAULT 'queued',
 result LONGTEXT NULL,
 log MEDIUMTEXT NOT NULL DEFAULT '',
 error TEXT NULL,
 backup_id BIGINT UNSIGNED NULL,
 started_at DATETIME NULL,
 ended_at DATETIME NULL,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 INDEX job_status(status), INDEX backup_history(backup_id, created_at)
);
CREATE TABLE IF NOT EXISTS events (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 kind VARCHAR(64) NOT NULL,
 severity ENUM('info','warning','error') NOT NULL DEFAULT 'info',
 message TEXT NOT NULL,
 actor_id BIGINT UNSIGNED NULL,
 acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 INDEX event_time(created_at)
);
CREATE TABLE IF NOT EXISTS audit (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 actor_id BIGINT UNSIGNED NULL,
 action VARCHAR(80) NOT NULL,
 details TEXT NOT NULL,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS request_nonces (
 nonce CHAR(32) PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT IGNORE INTO settings(name,value) VALUES
 ('monitoring','{"profile":"balanced","capacity":300,"smart":3600,"shares":60,"services":60,"backups":60,"reconcile":300}');
INSERT IGNORE INTO schema_versions(version) VALUES (1);
