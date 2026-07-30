USE rtools_marketplace;
ALTER TABLE plugins ADD COLUMN trust_level ENUM('community','verified','official') NOT NULL DEFAULT 'community';
INSERT IGNORE INTO schema_migrations(version) VALUES ('005_plugin_trust');
