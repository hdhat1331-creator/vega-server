-- VEGA test environment only. Safe to apply after the existing migrations.
-- Existing users.bio and users.avatar_key columns are intentionally not recreated.

ALTER TABLE users ADD COLUMN last_seen_at INTEGER;
ALTER TABLE users ADD COLUMN last_seen_visibility TEXT NOT NULL DEFAULT 'everyone' CHECK(last_seen_visibility IN ('everyone','nobody'));
ALTER TABLE conversation_members ADD COLUMN last_read_at INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS message_reads (
  message_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  read_at INTEGER NOT NULL,
  PRIMARY KEY (message_id, user_id),
  FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_message_reads_user_read_at
  ON message_reads(user_id, read_at);
CREATE INDEX IF NOT EXISTS idx_message_reads_message
  ON message_reads(message_id);
CREATE INDEX IF NOT EXISTS idx_conversation_members_last_read
  ON conversation_members(user_id, last_read_at);
CREATE INDEX IF NOT EXISTS idx_users_last_seen
  ON users(last_seen_at);
