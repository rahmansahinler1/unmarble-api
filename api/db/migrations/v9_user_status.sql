-- Migration: v9_user_status
-- Description: Replace first_time boolean with user_status enum for onboarding/tour flow
-- Date: 2025-12-30

-- Step 1: Add user_status column with default 'first_time' for new users
ALTER TABLE users ADD COLUMN user_status VARCHAR(20) DEFAULT 'first_time';

-- Step 2: Migrate existing users who completed onboarding to 'onboarded'
-- Users with first_time = false are considered to have completed onboarding
UPDATE users SET user_status = 'onboarded' WHERE first_time = false;
-- Users with first_time = true stay as 'first_time' (default value)

-- Step 3: Make user_status NOT NULL now that all rows have values
ALTER TABLE users ALTER COLUMN user_status SET NOT NULL;

-- Step 4: Add CHECK constraint to enforce enum values
ALTER TABLE users ADD CONSTRAINT user_status_check
    CHECK (user_status IN ('first_time', 'onboarded', 'active'));

-- Step 5: Drop old first_time column
ALTER TABLE users DROP COLUMN first_time;
