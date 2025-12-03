-- Migration: Add first_time and gender columns for user onboarding
-- first_time: tracks whether a user has completed the onboarding flow
-- gender: stores user's gender selection from onboarding (nullable)

ALTER TABLE users ADD COLUMN first_time BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN gender VARCHAR(10) DEFAULT NULL;
