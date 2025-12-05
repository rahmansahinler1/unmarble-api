-- Migration: Create defaults table for onboarding clothing images
-- This table stores pre-loaded clothing images shown during onboarding

-- Step 1: Modify images table to use composite primary key
-- This allows the same image_id (UUID) to exist for multiple users
-- (needed when copying default images to user's images table)
ALTER TABLE images DROP CONSTRAINT images_pkey;
ALTER TABLE images ADD PRIMARY KEY (user_id, image_id);

-- Step 2: Create defaults table with SERIAL id as primary key and UUID image_id
CREATE TABLE defaults (
    id SERIAL PRIMARY KEY,
    image_id UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    gender VARCHAR(10) NOT NULL,
    image_bytes BYTEA NOT NULL,
    preview_bytes BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Update default limits
ALTER TABLE users
ALTER COLUMN storage_left SET DEFAULT 10,
ALTER COLUMN designs_left SET DEFAULT 2;