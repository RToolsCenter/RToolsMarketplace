CREATE DATABASE IF NOT EXISTS rtools_marketplace CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE rtools_marketplace;

CREATE TABLE IF NOT EXISTS developers (
  id CHAR(36) PRIMARY KEY, display_name VARCHAR(80) NOT NULL, email VARCHAR(255) NOT NULL UNIQUE,
  status ENUM('active','suspended') NOT NULL DEFAULT 'active', public_key TEXT,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3), updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS api_tokens (
  id CHAR(36) PRIMARY KEY, developer_id CHAR(36) NOT NULL, token_hash CHAR(64) NOT NULL UNIQUE,
  name VARCHAR(80) NOT NULL DEFAULT 'default', last_used_at TIMESTAMP(3) NULL, expires_at TIMESTAMP(3) NULL, revoked_at TIMESTAMP(3) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3), FOREIGN KEY(developer_id) REFERENCES developers(id) ON DELETE CASCADE
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS plugins (
  id VARCHAR(128) PRIMARY KEY, owner_id CHAR(36) NOT NULL, name VARCHAR(80) NOT NULL, summary VARCHAR(240), description TEXT,
  icon_url TEXT, homepage TEXT, repository TEXT, license VARCHAR(40), status ENUM('draft','published','suspended') NOT NULL DEFAULT 'draft',
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3), updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  FOREIGN KEY(owner_id) REFERENCES developers(id), INDEX idx_plugins_owner(owner_id), INDEX idx_plugins_status(status)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS plugin_versions (
  id CHAR(36) PRIMARY KEY, plugin_id VARCHAR(128) NOT NULL, version VARCHAR(64) NOT NULL, schema_version INT NOT NULL,
  min_host_version VARCHAR(64) NOT NULL, max_host_version VARCHAR(64), entry_type VARCHAR(24) NOT NULL,
  package_url TEXT, package_sha256 CHAR(64) NOT NULL, package_size BIGINT UNSIGNED NOT NULL,
  developer_signature LONGTEXT, market_signature LONGTEXT, permissions_json JSON NOT NULL, file_manifest_json JSON NOT NULL, manifest_json JSON NOT NULL,
  changelog TEXT, review_status ENUM('pending_scan','scan_failed','pending_review','approved','rejected','published','unpublished') NOT NULL DEFAULT 'pending_scan',
  published_at TIMESTAMP(3) NULL, created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_plugin_version(plugin_id,version), FOREIGN KEY(plugin_id) REFERENCES plugins(id) ON DELETE CASCADE, INDEX idx_versions_review(review_status)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS plugin_permissions (
  plugin_version_id CHAR(36) NOT NULL, permission VARCHAR(128) NOT NULL, scope VARCHAR(255) NOT NULL DEFAULT '', required_flag BOOLEAN NOT NULL DEFAULT TRUE, reason TEXT,
  PRIMARY KEY(plugin_version_id,permission,scope), FOREIGN KEY(plugin_version_id) REFERENCES plugin_versions(id) ON DELETE CASCADE
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS reviews (
  id CHAR(36) PRIMARY KEY, plugin_version_id CHAR(36) NOT NULL, status VARCHAR(32) NOT NULL, automated_report_json JSON,
  reviewer_id VARCHAR(128), review_note TEXT, created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3), updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  FOREIGN KEY(plugin_version_id) REFERENCES plugin_versions(id) ON DELETE CASCADE, INDEX idx_reviews_version(plugin_version_id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, actor_id VARCHAR(128), action VARCHAR(80) NOT NULL, target VARCHAR(255), details JSON,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3), INDEX idx_audit_actor(actor_id), INDEX idx_audit_created(created_at)
) ENGINE=InnoDB;
