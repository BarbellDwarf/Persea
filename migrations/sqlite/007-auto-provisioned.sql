-- Auto-provisioned group marker (ticket F38): boolean flag on local_groups
-- so the UI can distinguish provider-synced groups from manually created ones.
ALTER TABLE local_groups ADD COLUMN auto_provisioned INTEGER NOT NULL DEFAULT 0;
