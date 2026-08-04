-- Short-lived, single-use approvals for least-privilege server-side operator actions.
-- The approval phrase is never stored; only its SHA-256 digest is persisted.
CREATE TABLE operator_action_approvals (
    community_id      UUID NOT NULL REFERENCES communities(id),
    id                UUID NOT NULL,
    action            TEXT NOT NULL CHECK (action IN ('delete_channel')),
    actor_pubkey      BYTEA NOT NULL CHECK (length(actor_pubkey) = 32),
    target_id         UUID NOT NULL,
    target_snapshot   JSONB NOT NULL CHECK (jsonb_typeof(target_snapshot) = 'object'),
    reason            TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 1000),
    approval_hash     BYTEA NOT NULL CHECK (length(approval_hash) = 32),
    request_event_id  BYTEA NOT NULL CHECK (length(request_event_id) = 32),
    status            TEXT NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'executed', 'expired')),
    requested_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL,
    executed_at       TIMESTAMPTZ,
    approval_event_id BYTEA CHECK (
        approval_event_id IS NULL OR length(approval_event_id) = 32
    ),
    approved_by_pubkey BYTEA CHECK (
        approved_by_pubkey IS NULL OR length(approved_by_pubkey) = 32
    ),
    CHECK (
        (status = 'executed' AND executed_at IS NOT NULL
            AND approval_event_id IS NOT NULL AND approved_by_pubkey IS NOT NULL)
        OR
        (status <> 'executed' AND executed_at IS NULL
            AND approval_event_id IS NULL AND approved_by_pubkey IS NULL)
    ),
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, approval_hash),
    UNIQUE (community_id, request_event_id),
    UNIQUE (community_id, approval_event_id),
    FOREIGN KEY (community_id, target_id)
        REFERENCES channels (community_id, id)
);

CREATE INDEX idx_operator_action_approvals_pending
    ON operator_action_approvals (community_id, expires_at)
    WHERE status = 'pending';
