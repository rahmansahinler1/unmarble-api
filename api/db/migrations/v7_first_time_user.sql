-- Migration: Add first_time column for user onboarding
-- This column tracks whether a user has completed the onboarding flow

ALTER TABLE users ADD COLUMN first_time BOOLEAN NOT NULL DEFAULT true;
