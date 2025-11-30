-- Migration: v6_subscription_status
-- Description: Add subscription tracking fields for Lemon Squeezy webhook integration
-- Date: 2025-11-30

-- Add subscription tracking fields
ALTER TABLE users
ADD COLUMN subscription_status VARCHAR(20) DEFAULT 'none',
ADD COLUMN subscription_id VARCHAR(255) DEFAULT NULL,
ADD COLUMN subscription_ends_at TIMESTAMP DEFAULT NULL;

-- Update existing premium users to have 'active' status
UPDATE users SET subscription_status = 'active' WHERE user_type = 'premium';
