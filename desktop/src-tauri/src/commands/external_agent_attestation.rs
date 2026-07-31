use nostr::Keys;
use tauri::State;

use crate::app_state::AppState;

fn compute_external_agent_auth_tag(
    owner_keys: &Keys,
    agent_pubkey: &str,
) -> Result<String, String> {
    let agent_pubkey = agent_pubkey.trim();
    let agent_keys = nostr::PublicKey::from_hex(agent_pubkey)
        .map_err(|e| format!("invalid agent public key: {e}"))?;
    if owner_keys.public_key() == agent_keys {
        return Err("the owner identity cannot attest itself as an agent".to_string());
    }

    let compat_owner = nostr::Keys::parse(&owner_keys.secret_key().to_secret_hex())
        .map_err(|e| format!("failed to bridge owner keys: {e}"))?;
    buzz_sdk_pkg::nip_oa::compute_auth_tag(&compat_owner, &agent_keys, "")
        .map_err(|e| format!("failed to compute NIP-OA auth tag: {e}"))
}

/// Sign a NIP-OA owner attestation for an existing external agent identity.
/// The owner key stays in Buzz Desktop; only the public authorization tag is returned.
#[tauri::command]
pub fn attest_external_agent(
    agent_pubkey: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    compute_external_agent_auth_tag(&state.signing_keys()?, &agent_pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_tag_authorizes_the_supplied_agent_key() {
        let owner_keys = Keys::generate();
        let agent_keys = Keys::generate();
        let agent_pubkey = agent_keys.public_key().to_hex();

        let auth_tag = compute_external_agent_auth_tag(&owner_keys, &agent_pubkey)
            .expect("a distinct valid agent pubkey should be attestable");
        let compat_agent = nostr::PublicKey::from_hex(&agent_pubkey).expect("valid pubkey");
        let verified_owner = buzz_sdk_pkg::nip_oa::verify_auth_tag(&auth_tag, &compat_agent)
            .expect("generated auth tag should verify");

        assert_eq!(verified_owner.to_hex(), owner_keys.public_key().to_hex());
    }
}
