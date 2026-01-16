-- Migrate 'active' users to 'onboarded' status
-- Tour is now optional and manual-only, no longer part of onboarding flow

BEGIN;

-- Update CHECK constraint to only allow 'first_time' and 'onboarded'
ALTER TABLE users
DROP CONSTRAINT IF EXISTS users_user_status_check;

ALTER TABLE users
ADD CONSTRAINT users_user_status_check
CHECK (user_status IN ('first_time', 'onboarded'));

-- Update default limits
ALTER TABLE users
ALTER COLUMN storage_left SET DEFAULT 20,
ALTER COLUMN designs_left SET DEFAULT 5;
