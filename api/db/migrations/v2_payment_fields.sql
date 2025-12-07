-- Add Lemon Squeezy payment tracking columns
ALTER TABLE users ADD COLUMN IF NOT EXISTS lemon_squeezy_customer_id VARCHAR(255) DEFAULT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS receipt_url VARCHAR(500) DEFAULT NULL;
