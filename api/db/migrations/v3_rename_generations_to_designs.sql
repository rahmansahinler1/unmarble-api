-- Migration: Rename generations table to designs and update user credits
-- Purpose: Align table and column naming with UX terminology (Designed images)
-- Date: 2025-11-23

-- Rename the generations table to designs
ALTER TABLE generations RENAME TO designs;
-- Rename the generations_left column to designs_left in users table
ALTER TABLE users RENAME COLUMN generations_left TO designs_left;
