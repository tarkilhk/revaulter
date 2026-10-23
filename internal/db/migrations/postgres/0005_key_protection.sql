ALTER TABLE v2_user_credentials ADD COLUMN key_protection TEXT NOT NULL DEFAULT 'prf' CHECK (key_protection IN ('prf', 'bitwarden'));
