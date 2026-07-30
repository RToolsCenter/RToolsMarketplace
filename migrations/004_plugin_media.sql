USE rtools_marketplace;
ALTER TABLE plugins ADD COLUMN screenshots_json JSON NULL;
INSERT IGNORE INTO schema_migrations(version) VALUES ('004_plugin_media');
