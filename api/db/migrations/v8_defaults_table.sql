-- Migration: Create defaults table for onboarding clothing images
-- This table stores pre-loaded clothing images shown during onboarding

CREATE TABLE defaults (
    id SERIAL PRIMARY KEY,
    gender VARCHAR(10) NOT NULL,
    image_bytes BYTEA NOT NULL,
    preview_bytes BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for faster gender-based queries
CREATE INDEX idx_defaults_gender ON defaults(gender);
