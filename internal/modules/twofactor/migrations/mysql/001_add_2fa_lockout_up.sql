ALTER TABLE two_factors ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE two_factors ADD COLUMN locked_until DATETIME;
