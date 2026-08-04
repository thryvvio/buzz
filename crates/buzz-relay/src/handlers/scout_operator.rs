use std::sync::Arc;

use anyhow::{bail, Context as _};
use buzz_audit::{AuditAction, NewAuditEntry};
use buzz_core::TenantContext;
use chrono::{DateTime, Duration, Utc};
use nostr::Event;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::state::AppState;

const MAX_REASON_BYTES: usize = 1_000;
const MAX_APPROVAL_LIFETIME_SECS: i64 = 15 * 60;

pub(crate) fn canonical_channel_delete_approval(
    tenant: &str,
    channel: Uuid,
    request: Uuid,
    nonce: Uuid,
    expires: DateTime<Utc>,
) -> String {
    format!(
        "APPROVE BUZZ CHANNEL_DELETE tenant={tenant} channel={channel} request={request} nonce={nonce} expires={}",
        expires.timestamp()
    )
}

pub(crate) fn is_scout_routine_authorized(
    actor: &str,
    configured_scout: Option<&str>,
    relay_role: Option<&str>,
) -> bool {
    configured_scout == Some(actor) && matches!(relay_role, Some("admin" | "owner"))
}

pub(crate) async fn has_routine_authority(
    tenant: &TenantContext,
    state: &AppState,
    actor_hex: &str,
) -> anyhow::Result<bool> {
    if state.config.scout_operator_pubkey.as_deref() != Some(actor_hex) {
        return Ok(false);
    }
    let role = state
        .db
        .get_relay_member(tenant.community(), actor_hex)
        .await?
        .map(|member| member.role);
    Ok(is_scout_routine_authorized(
        actor_hex,
        state.config.scout_operator_pubkey.as_deref(),
        role.as_deref(),
    ))
}

fn tag(event: &Event, name: &str) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let values = tag.as_slice();
        (values.first().map(String::as_str) == Some(name))
            .then(|| values.get(1).cloned())
            .flatten()
    })
}

fn parse_uuid_tag(event: &Event, name: &str) -> anyhow::Result<Uuid> {
    Uuid::parse_str(&tag(event, name).with_context(|| format!("missing {name} tag"))?)
        .with_context(|| format!("invalid {name} tag"))
}

fn hash_text(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    expected.len() == actual.len()
        && expected
            .iter()
            .zip(actual)
            .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

fn ensure_pending(status: &str) -> anyhow::Result<()> {
    if status != "pending" {
        bail!("operator request is {status}; approvals are single-use");
    }
    Ok(())
}

async fn require_current_scout(
    tenant: &TenantContext,
    state: &AppState,
    event: &Event,
) -> anyhow::Result<()> {
    if !has_routine_authority(tenant, state, &event.pubkey.to_hex()).await? {
        bail!("actor not authorized: configured Scout must be a current relay admin or owner");
    }
    Ok(())
}

async fn require_locked_relay_role(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &TenantContext,
    pubkey_hex: &str,
    accepted_roles: &[&str],
    error: &str,
) -> anyhow::Result<()> {
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM relay_members WHERE community_id=$1 AND pubkey=$2 FOR SHARE",
    )
    .bind(tenant.community().as_uuid())
    .bind(pubkey_hex)
    .fetch_optional(&mut **tx)
    .await?;
    if !role
        .as_deref()
        .is_some_and(|role| accepted_roles.contains(&role))
    {
        bail!("{error}");
    }
    Ok(())
}

fn validate_fresh_command(event: &Event) -> anyhow::Result<()> {
    let now = Utc::now().timestamp();
    let created = i64::try_from(event.created_at.as_secs()).context("timestamp out of range")?;
    if (created - now).abs() > 120 {
        bail!("operator command timestamp out of range");
    }
    Ok(())
}

async fn audit(state: &AppState, entry: NewAuditEntry) {
    if let Some(tx) = &state.audit_tx {
        if let Err(error) = tx.send(entry).await {
            tracing::warn!(%error, "failed to queue Scout operator audit entry");
        }
    }
}

async fn claim_admin(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    event: &Event,
) -> anyhow::Result<()> {
    if state.config.scout_operator_pubkey.as_deref() != Some(event.pubkey.to_hex().as_str()) {
        bail!("actor not authorized: configured Scout required");
    }
    validate_fresh_command(event)?;
    let channel = parse_uuid_tag(event, "channel")?;
    let reason = event.content.trim();
    if reason.is_empty() || reason.len() > MAX_REASON_BYTES {
        bail!("reason must contain 1 to 1000 bytes");
    }

    let actor_hex = event.pubkey.to_hex();
    let actor = event.pubkey.to_bytes();
    let mut tx = state.db.writer_pool().begin().await?;
    require_locked_relay_role(
        &mut tx,
        tenant,
        &actor_hex,
        &["admin", "owner"],
        "actor not authorized: configured Scout must be a current relay admin or owner",
    )
    .await?;
    sqlx::query(
        "SELECT 1 FROM channels WHERE community_id=$1 AND id=$2 AND deleted_at IS NULL FOR SHARE",
    )
    .bind(tenant.community().as_uuid())
    .bind(channel)
    .fetch_optional(&mut *tx)
    .await?
    .context("target channel not found")?;

    sqlx::query(
        "INSERT INTO channel_members \
         (community_id,channel_id,pubkey,role,invited_by,removed_at,removed_by) \
         VALUES ($1,$2,$3,'admin',$3,NULL,NULL) \
         ON CONFLICT (community_id,channel_id,pubkey) DO UPDATE SET \
           role=CASE \
             WHEN channel_members.removed_at IS NULL AND channel_members.role='owner' \
             THEN 'owner'::member_role ELSE 'admin'::member_role END, \
           invited_by=EXCLUDED.invited_by,removed_at=NULL,removed_by=NULL",
    )
    .bind(tenant.community().as_uuid())
    .bind(channel)
    .bind(actor.as_slice())
    .execute(&mut *tx)
    .await
    .context("claim routine channel admin membership")?;
    tx.commit().await?;
    state.invalidate_membership(tenant, channel, actor.as_slice());
    state.invalidate_all_accessible_channels(tenant);
    audit(
        state,
        NewAuditEntry {
            community_id: tenant.community(),
            action: AuditAction::OperatorActionExecuted,
            actor_pubkey: Some(actor.to_vec()),
            object_id: Some(channel.to_string()),
            detail: serde_json::json!({
                "operator_action": "claim_channel_admin",
                "channel_id": channel,
                "reason": reason,
                "command_event_id": event.id.to_hex(),
                "authority": "admin_not_owner",
            }),
        },
    )
    .await;
    Ok(())
}

async fn prepare(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    event: &Event,
) -> anyhow::Result<()> {
    require_current_scout(tenant, state, event).await?;
    validate_fresh_command(event)?;

    let request = parse_uuid_tag(event, "request")?;
    let nonce = parse_uuid_tag(event, "nonce")?;
    let channel = parse_uuid_tag(event, "channel")?;
    let tenant_tag = tag(event, "tenant").context("missing tenant tag")?;
    if tenant_tag != tenant.host() {
        bail!("tenant tag does not match the resolved community");
    }
    let expiry_seconds: i64 = tag(event, "expires")
        .context("missing expires tag")?
        .parse()
        .context("invalid expires tag")?;
    let expires = DateTime::<Utc>::from_timestamp(expiry_seconds, 0)
        .context("expires timestamp out of range")?;
    let now = Utc::now();
    if expires <= now || expires > now + Duration::seconds(MAX_APPROVAL_LIFETIME_SECS) {
        bail!("approval expiry must be in the next 15 minutes");
    }
    let reason = event.content.trim();
    if reason.is_empty() || reason.len() > MAX_REASON_BYTES {
        bail!("reason must contain 1 to 1000 bytes");
    }
    let channel_row = state
        .db
        .get_channel(tenant.community(), channel)
        .await
        .context("target channel not found")?;
    let snapshot = serde_json::json!({
        "id": channel,
        "name": channel_row.name,
        "visibility": channel_row.visibility,
        "created_by": hex::encode(channel_row.created_by),
    });
    let statement =
        canonical_channel_delete_approval(tenant.host(), channel, request, nonce, expires);

    sqlx::query(
        "INSERT INTO operator_action_approvals \
         (community_id, id, action, actor_pubkey, target_id, target_snapshot, reason, approval_hash, request_event_id, requested_at, expires_at) \
         VALUES ($1,$2,'delete_channel',$3,$4,$5,$6,$7,$8,to_timestamp($9),$10)",
    )
    .bind(tenant.community().as_uuid())
    .bind(request)
    .bind(event.pubkey.to_bytes().as_slice())
    .bind(channel)
    .bind(&snapshot)
    .bind(reason)
    .bind(hash_text(&statement).as_slice())
    .bind(event.id.as_bytes().as_slice())
    .bind(i64::try_from(event.created_at.as_secs())?)
    .bind(expires)
    .execute(state.db.writer_pool())
    .await
    .context("store operator request")?;

    audit(
        state,
        NewAuditEntry {
            community_id: tenant.community(),
            action: AuditAction::OperatorActionRequested,
            actor_pubkey: Some(event.pubkey.to_bytes().to_vec()),
            object_id: Some(request.to_string()),
            detail: serde_json::json!({
                "operator_action": "delete_channel",
                "channel": snapshot,
                "reason": reason,
                "expires_at": expires,
                "request_event_id": event.id.to_hex(),
            }),
        },
    )
    .await;
    Ok(())
}

fn validate_approval(
    event: &Event,
    actor: &[u8],
    expected_hash: &[u8],
    requested_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> anyhow::Result<[u8; 32]> {
    event
        .verify()
        .context("invalid approval event signature or id")?;
    if u32::from(event.kind.as_u16()) != buzz_core::kind::KIND_STREAM_MESSAGE {
        bail!("approval event must be kind 9");
    }
    let signer = event.pubkey.to_bytes();
    if signer.as_slice() == actor {
        bail!("Scout cannot approve its own request");
    }
    if !constant_time_eq(expected_hash, &hash_text(&event.content)) {
        bail!("approval content does not exactly match the prepared request");
    }
    let signed_at = DateTime::<Utc>::from_timestamp(i64::try_from(event.created_at.as_secs())?, 0)
        .context("approval timestamp out of range")?;
    if signed_at < requested_at || signed_at > expires_at {
        bail!("approval event is outside the request window");
    }
    Ok(signer)
}

async fn execute(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    event: &Event,
) -> anyhow::Result<()> {
    require_current_scout(tenant, state, event).await?;
    validate_fresh_command(event)?;
    let request_id = parse_uuid_tag(event, "request")?;
    let approval_tag = tag(event, "approval").context("missing approval tag")?;
    let approval_id = nostr::EventId::parse(&approval_tag).context("invalid approval event id")?;
    let stored = state
        .db
        .get_event_by_id(tenant.community(), approval_id.as_bytes())
        .await?
        .context("approval event not found in this community")?;

    let mut tx = state.db.writer_pool().begin().await?;
    let request = sqlx::query(
        "SELECT target_id,target_snapshot,reason,approval_hash,status,requested_at,expires_at \
         FROM operator_action_approvals \
         WHERE community_id=$1 AND id=$2 AND action='delete_channel' AND actor_pubkey=$3 FOR UPDATE",
    )
    .bind(tenant.community().as_uuid())
    .bind(request_id)
    .bind(event.pubkey.to_bytes().as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .context("prepared operator request not found")?;
    let status: String = request.try_get("status")?;
    ensure_pending(&status)?;
    let requested_at: DateTime<Utc> = request.try_get("requested_at")?;
    let expires_at: DateTime<Utc> = request.try_get("expires_at")?;
    if Utc::now() > expires_at {
        sqlx::query("UPDATE operator_action_approvals SET status='expired' WHERE community_id=$1 AND id=$2 AND status='pending'")
            .bind(tenant.community().as_uuid())
            .bind(request_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        bail!("operator request expired");
    }
    let expected_hash: Vec<u8> = request.try_get("approval_hash")?;
    let approver = validate_approval(
        &stored.event,
        event.pubkey.as_bytes(),
        &expected_hash,
        requested_at,
        expires_at,
    )?;
    let approver_hex = hex::encode(approver);
    if state.config.relay_owner_pubkey.as_deref() != Some(approver_hex.as_str()) {
        bail!("approval signer is not the configured human relay owner");
    }
    if state.config.scout_operator_pubkey.as_deref() != Some(event.pubkey.to_hex().as_str()) {
        bail!("actor not authorized: configured Scout required");
    }
    require_locked_relay_role(
        &mut tx,
        tenant,
        &event.pubkey.to_hex(),
        &["admin", "owner"],
        "actor not authorized: configured Scout must be a current relay admin or owner",
    )
    .await?;
    require_locked_relay_role(
        &mut tx,
        tenant,
        &approver_hex,
        &["owner"],
        "approval signer is not a current human relay owner",
    )
    .await?;

    let channel_id: Uuid = request.try_get("target_id")?;
    let deleted = sqlx::query(
        "UPDATE channels SET deleted_at=NOW() WHERE community_id=$1 AND id=$2 AND deleted_at IS NULL",
    )
    .bind(tenant.community().as_uuid())
    .bind(channel_id)
    .execute(&mut *tx)
    .await?;
    if deleted.rows_affected() != 1 {
        bail!("target channel is already deleted or missing");
    }
    sqlx::query(
        "UPDATE events SET deleted_at=NOW() \
         WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3 \
           AND deleted_at IS NULL AND kind IN (39000,39001,39002)",
    )
    .bind(tenant.community().as_uuid())
    .bind(channel_id)
    .bind(state.relay_keypair.public_key().as_bytes())
    .execute(&mut *tx)
    .await?;
    let consumed = sqlx::query(
        "UPDATE operator_action_approvals SET status='executed',executed_at=NOW(),approval_event_id=$3,approved_by_pubkey=$4 \
         WHERE community_id=$1 AND id=$2 AND status='pending'",
    )
    .bind(tenant.community().as_uuid())
    .bind(request_id)
    .bind(approval_id.as_bytes().as_slice())
    .bind(approver.as_slice())
    .execute(&mut *tx)
    .await?;
    if consumed.rows_affected() != 1 {
        bail!("operator request was concurrently consumed");
    }
    tx.commit().await?;

    state.invalidate_channel_deleted(tenant);
    audit(
        state,
        NewAuditEntry {
            community_id: tenant.community(),
            action: AuditAction::OperatorActionExecuted,
            actor_pubkey: Some(event.pubkey.to_bytes().to_vec()),
            object_id: Some(request_id.to_string()),
            detail: serde_json::json!({
                "operator_action": "delete_channel",
                "channel": request.try_get::<serde_json::Value, _>("target_snapshot")?,
                "reason": request.try_get::<String, _>("reason")?,
                "approval_event_id": approval_id.to_hex(),
                "approved_by_pubkey": hex::encode(approver),
                "execute_event_id": event.id.to_hex(),
            }),
        },
    )
    .await;
    tracing::info!(community=%tenant.community(), %channel_id, %request_id, "Scout operator channel deletion executed");
    Ok(())
}

pub(super) async fn handle_event(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    event: &Event,
) -> anyhow::Result<()> {
    match u32::from(event.kind.as_u16()) {
        buzz_core::kind::SCOUT_CHANNEL_CLAIM_ADMIN => claim_admin(tenant, state, event).await,
        buzz_core::kind::SCOUT_CHANNEL_DELETE_PREPARE => prepare(tenant, state, event).await,
        buzz_core::kind::SCOUT_CHANNEL_DELETE_EXECUTE => execute(tenant, state, event).await,
        _ => bail!("unexpected Scout operator event kind"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_approval_binds_tenant_channel_request_nonce_and_expiry() {
        let expires = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).expect("timestamp");
        let text = canonical_channel_delete_approval(
            "tenant.example",
            Uuid::from_u128(0xaaaa),
            Uuid::from_u128(0xbbbb),
            Uuid::from_u128(0xcccc),
            expires,
        );
        assert_eq!(text, "APPROVE BUZZ CHANNEL_DELETE tenant=tenant.example channel=00000000-0000-0000-0000-00000000aaaa request=00000000-0000-0000-0000-00000000bbbb nonce=00000000-0000-0000-0000-00000000cccc expires=1800000000");
    }

    #[test]
    fn only_configured_scout_with_current_relay_admin_role_gets_routine_bridge() {
        assert!(is_scout_routine_authorized("aa", Some("aa"), Some("admin")));
        assert!(is_scout_routine_authorized("aa", Some("aa"), Some("owner")));
        assert!(!is_scout_routine_authorized(
            "bb",
            Some("aa"),
            Some("admin")
        ));
        assert!(!is_scout_routine_authorized(
            "aa",
            Some("aa"),
            Some("member")
        ));
        assert!(!is_scout_routine_authorized("aa", None, Some("admin")));
    }

    #[test]
    fn approval_rejects_self_wrong_kind_wrong_content_and_expiry() {
        let scout = nostr::Keys::generate();
        let owner = nostr::Keys::generate();
        let now = Utc::now();
        let phrase = "exact";
        let signed = |keys: &nostr::Keys, kind: nostr::Kind, content: &str, at: i64| {
            nostr::EventBuilder::new(kind, content)
                .custom_created_at(nostr::Timestamp::from(at as u64))
                .sign_with_keys(keys)
                .expect("sign")
        };
        let expected = hash_text(phrase);
        assert!(validate_approval(
            &signed(&owner, nostr::Kind::Custom(9), phrase, now.timestamp()),
            scout.public_key().as_bytes(),
            &expected,
            now - Duration::seconds(1),
            now + Duration::seconds(1)
        )
        .is_ok());
        assert!(validate_approval(
            &signed(&scout, nostr::Kind::Custom(9), phrase, now.timestamp()),
            scout.public_key().as_bytes(),
            &expected,
            now - Duration::seconds(1),
            now + Duration::seconds(1)
        )
        .is_err());
        assert!(validate_approval(
            &signed(&owner, nostr::Kind::Metadata, phrase, now.timestamp()),
            scout.public_key().as_bytes(),
            &expected,
            now - Duration::seconds(1),
            now + Duration::seconds(1)
        )
        .is_err());
        assert!(validate_approval(
            &signed(&owner, nostr::Kind::Custom(9), "wrong", now.timestamp()),
            scout.public_key().as_bytes(),
            &expected,
            now - Duration::seconds(1),
            now + Duration::seconds(1)
        )
        .is_err());
        assert!(validate_approval(
            &signed(&owner, nostr::Kind::Custom(9), phrase, now.timestamp() + 2),
            scout.public_key().as_bytes(),
            &expected,
            now - Duration::seconds(1),
            now + Duration::seconds(1)
        )
        .is_err());
    }

    async fn integration_state(
        pool: sqlx::PgPool,
        scout: &nostr::Keys,
        owner: &nostr::Keys,
        tenant_host: &str,
    ) -> Arc<AppState> {
        let db = buzz_db::Db::from_pool(pool.clone());
        let mut config = crate::config::Config::from_env().expect("test config");
        config.database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .expect("test database URL");
        config.redis_url = std::env::var("BUZZ_TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:56379".to_string());
        config.relay_url = format!("wss://{tenant_host}");
        config.scout_operator_pubkey = Some(scout.public_key().to_hex());
        config.relay_owner_pubkey = Some(owner.public_key().to_hex());
        config.audit_enabled = true;
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("pubsub"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).expect("media storage");
        let (state, _audit_shutdown) = crate::state::AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            nostr::Keys::generate(),
            media_storage,
        );
        Arc::new(state)
    }

    fn operator_event(
        keys: &nostr::Keys,
        kind: u32,
        content: &str,
        tags: impl IntoIterator<Item = nostr::Tag>,
    ) -> Event {
        nostr::EventBuilder::new(nostr::Kind::Custom(kind as u16), content)
            .tags(tags)
            .sign_with_keys(keys)
            .expect("sign operator event")
    }

    #[tokio::test]
    #[ignore = "requires Postgres and Redis"]
    async fn database_flow_claims_admin_deletes_once_and_rejects_replay() {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .expect("BUZZ_TEST_DATABASE_URL or DATABASE_URL");
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect test database");
        buzz_db::Db::from_pool(pool.clone())
            .migrate()
            .await
            .expect("migrate test database");

        let scout = nostr::Keys::generate();
        let owner = nostr::Keys::generate();
        let tenant_uuid = Uuid::new_v4();
        let tenant_host = format!("operator-{}.example", tenant_uuid.simple());
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(tenant_uuid)
            .bind(&tenant_host)
            .execute(&pool)
            .await
            .expect("insert test community");
        let tenant = TenantContext::resolved(
            buzz_core::CommunityId::from_uuid(tenant_uuid),
            tenant_host.clone(),
        );
        let state = integration_state(pool.clone(), &scout, &owner, &tenant_host).await;
        state
            .db
            .add_relay_member(
                tenant.community(),
                &owner.public_key().to_hex(),
                "owner",
                None,
            )
            .await
            .expect("add owner");
        state
            .db
            .add_relay_member(
                tenant.community(),
                &scout.public_key().to_hex(),
                "admin",
                Some(&owner.public_key().to_hex()),
            )
            .await
            .expect("add Scout");
        let channel = state
            .db
            .create_channel(
                tenant.community(),
                "operator bridge test",
                buzz_db::channel::ChannelType::Stream,
                buzz_db::channel::ChannelVisibility::Private,
                None,
                owner.public_key().as_bytes(),
                None,
            )
            .await
            .expect("create channel");

        let channel_text = channel.id.to_string();
        let claim = operator_event(
            &scout,
            buzz_core::kind::SCOUT_CHANNEL_CLAIM_ADMIN,
            "recover test channel",
            [nostr::Tag::parse(["channel", channel_text.as_str()]).expect("channel tag")],
        );
        claim_admin(&tenant, &state, &claim)
            .await
            .expect("claim channel admin");
        assert_eq!(
            state
                .db
                .get_member_role(
                    tenant.community(),
                    channel.id,
                    scout.public_key().as_bytes(),
                )
                .await
                .expect("Scout role")
                .as_deref(),
            Some("admin")
        );

        let request = Uuid::new_v4();
        let nonce = Uuid::new_v4();
        let expires = Utc::now() + Duration::minutes(10);
        let request_text = request.to_string();
        let nonce_text = nonce.to_string();
        let expires_text = expires.timestamp().to_string();
        let prepare_event = operator_event(
            &scout,
            buzz_core::kind::SCOUT_CHANNEL_DELETE_PREPARE,
            "remove disposable test channel",
            [
                nostr::Tag::parse(["tenant", tenant_host.as_str()]).expect("tenant tag"),
                nostr::Tag::parse(["channel", channel_text.as_str()]).expect("channel tag"),
                nostr::Tag::parse(["request", request_text.as_str()]).expect("request tag"),
                nostr::Tag::parse(["nonce", nonce_text.as_str()]).expect("nonce tag"),
                nostr::Tag::parse(["expires", expires_text.as_str()]).expect("expires tag"),
            ],
        );
        prepare(&tenant, &state, &prepare_event)
            .await
            .expect("prepare deletion");

        let statement = canonical_channel_delete_approval(
            &tenant_host,
            channel.id,
            request,
            nonce,
            DateTime::<Utc>::from_timestamp(expires.timestamp(), 0).expect("expiry"),
        );
        let approval = nostr::EventBuilder::new(
            nostr::Kind::Custom(buzz_core::kind::KIND_STREAM_MESSAGE as u16),
            statement,
        )
        .sign_with_keys(&owner)
        .expect("sign approval");
        state
            .db
            .insert_event(tenant.community(), &approval, None)
            .await
            .expect("store approval");
        let approval_text = approval.id.to_hex();
        let execute_event = operator_event(
            &scout,
            buzz_core::kind::SCOUT_CHANNEL_DELETE_EXECUTE,
            "",
            [
                nostr::Tag::parse(["request", request_text.as_str()]).expect("request tag"),
                nostr::Tag::parse(["approval", approval_text.as_str()]).expect("approval tag"),
            ],
        );
        execute(&tenant, &state, &execute_event)
            .await
            .expect("execute deletion");
        assert!(
            state
                .db
                .get_channel(tenant.community(), channel.id)
                .await
                .is_err(),
            "channel must be deleted"
        );
        let status: String = sqlx::query_scalar(
            "SELECT status FROM operator_action_approvals WHERE community_id=$1 AND id=$2",
        )
        .bind(tenant.community().as_uuid())
        .bind(request)
        .fetch_one(&pool)
        .await
        .expect("approval status");
        assert_eq!(status, "executed");
        let replay = execute(&tenant, &state, &execute_event)
            .await
            .expect_err("replay must fail");
        assert!(replay.to_string().contains("single-use"), "{replay:#}");

        let mut audit_actions = Vec::new();
        for _ in 0..50 {
            audit_actions = sqlx::query_scalar::<_, String>(
                "SELECT action FROM audit_log WHERE community_id=$1 ORDER BY seq",
            )
            .bind(tenant.community().as_uuid())
            .fetch_all(&pool)
            .await
            .expect("read operator audit");
            if audit_actions.len() >= 3 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            audit_actions,
            vec![
                "operator_action_executed",
                "operator_action_requested",
                "operator_action_executed"
            ],
            "claim, prepare, and execute must all be durably audited"
        );
    }
}
