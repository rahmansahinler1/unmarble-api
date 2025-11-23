-- Migration v4: Merge storage limits
-- Combines uploads_left and recents_left into a single storage_left column
-- This simplifies the user experience from 3 limits to 2 limits

-- Step 1: Add new storage_left column
ALTER TABLE users
ADD COLUMN storage_left INTEGER NOT NULL DEFAULT 5;

-- Step 2: Migrate existing data
-- For existing users, sum their uploads_left and recents_left
UPDATE users
SET storage_left = COALESCE(uploads_left, 0) + COALESCE(recents_left, 0);

-- Step 3: Drop old columns
ALTER TABLE users
DROP COLUMN uploads_left,
DROP COLUMN recents_left;

-- Step 4: Update default values for new users
-- Trial users: 5 storage, 1 designs
-- Premium users: 50 storage, 20 designs
ALTER TABLE users
ALTER COLUMN storage_left SET DEFAULT 5,
ALTER COLUMN designs_left SET DEFAULT 1;

-- Note: Existing premium users will keep their migrated storage_left value
-- If you need to update existing premium users to 50 storage, run:
-- UPDATE users SET storage_left = 50 WHERE user_type = 'premium';
