-- Migration v5: Add NSFW violations tracking
-- Tracks content safety violation attempts for 3-strike policy enforcement
-- This demonstrates active monitoring and enforcement of content safety policies

-- Step 1: Add nsfw_violations column to users table
ALTER TABLE users
ADD COLUMN nsfw_violations INTEGER NOT NULL DEFAULT 0;

-- Step 2: Add column comment for documentation
COMMENT ON COLUMN users.nsfw_violations IS
'Number of NSFW content safety violations. Incremented each time Google Gemini blocks inappropriate content. 3+ violations may result in account suspension. Used for compliance monitoring and Lemon Squeezy payment processor requirements.';

-- Note: Existing users will have nsfw_violations = 0 by default
-- Violations are tracked automatically via the /design_image endpoint
