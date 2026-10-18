-- Reminder push (opt-in): a UTC minute under an opaque browser-derived id, and where to send an
-- empty push. Nothing here names a page, task, notebook or text.
CREATE TABLE reminders(id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, at TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX reminders_at ON reminders(at);
CREATE INDEX reminders_user ON reminders(user_id);
CREATE TABLE web_push_subscriptions(id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, endpoint TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, last_ok_at TEXT NOT NULL DEFAULT '');
CREATE INDEX web_push_subscriptions_user ON web_push_subscriptions(user_id);

-- Only an existing everyday account owns either, on insert and on any later re-point (as 0026).
CREATE TRIGGER reminders_everyday_only BEFORE INSERT ON reminders
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER reminders_everyday_only_update BEFORE UPDATE OF user_id ON reminders
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER web_push_subscriptions_everyday_only BEFORE INSERT ON web_push_subscriptions
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER web_push_subscriptions_everyday_only_update BEFORE UPDATE OF user_id ON web_push_subscriptions
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
