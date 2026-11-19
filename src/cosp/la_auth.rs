//! Execution-bound calculations. Authentication and membership are separate gates.
#[derive(Clone)]
pub(super) struct GrantBounds<'a> {
    pub(super) id: &'a str,
    pub(super) parent: Option<&'a str>,
    pub(super) run_until: Option<u64>,
    pub(super) execution_ceiling: Option<u64>,
}

/// Called only after the credential chain has been authenticated and authorized.
/// The result and each input term must be persisted with the job transaction;
/// this helper alone neither creates a mandate nor grants execution authority.
pub(super) fn mandate_limit(
    accepted: u64,
    runtime: u64,
    hard: u64,
    project: u64,
    chain: &[GrantBounds<'_>],
) -> Result<u64, &'static str> {
    if chain.is_empty() || chain.len() > 3 || runtime == 0 || runtime > 10_000 {
        return Err("delegation_denied");
    }
    let job = accepted.checked_add(runtime).ok_or("delegation_denied")?;
    if [accepted, job, hard, project]
        .iter()
        .any(|v| *v > i64::MAX as u64)
    {
        return Err("delegation_denied");
    }
    let mut limit = job.min(hard).min(project);
    let mut previous: Option<(&str, u64, u64)> = None;
    for (index, grant) in chain.iter().enumerate() {
        let run = grant.run_until.ok_or("delegation_denied")?;
        let ceiling = grant.execution_ceiling.ok_or("delegation_denied")?;
        if grant.id.is_empty()
            || run > i64::MAX as u64
            || ceiling > i64::MAX as u64
            || chain[..index].iter().any(|old| old.id == grant.id)
        {
            return Err("delegation_denied");
        }
        match previous {
            None if grant.parent.is_none() => (),
            Some((id, parent_run, parent_ceiling))
                if grant.parent == Some(id)
                    && run <= parent_run
                    && run <= parent_ceiling
                    && ceiling <= parent_ceiling => {}
            _ => return Err("delegation_denied"),
        }
        limit = limit.min(run).min(ceiling);
        previous = Some((grant.id, run, ceiling));
    }
    if limit <= accepted {
        return Err("delegation_denied");
    }
    Ok(limit)
}

/// Immutable input to a one-job mandate. This is not a credential or an
/// authorization decision; callers must first authenticate and authorize it.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MandateGrant {
    pub(super) id: String,
    pub(super) parent: Option<String>,
    pub(super) run_until: u64,
    pub(super) execution_ceiling: u64,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MandateDraft {
    pub(super) tenant: String,
    pub(super) project: String,
    pub(super) actor: String,
    pub(super) initiator: String,
    pub(super) lineage: String,
    pub(super) assignment: String,
    pub(super) job: String,
    pub(super) operation: String,
    pub(super) input_digest: String,
    pub(super) profile: String,
    pub(super) worker: String,
    pub(super) cpu_millicores: u64,
    pub(super) memory_bytes: u64,
    pub(super) storage_bytes: u64,
    pub(super) policy: String,
    pub(super) accepted_at: u64,
    pub(super) runtime_ms: u64,
    pub(super) assignment_hard: u64,
    pub(super) project_ceiling: u64,
    pub(super) chain: Vec<MandateGrant>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredMandate {
    pub(super) draft: MandateDraft,
    pub(super) max_until: u64,
}

/// Calculates a proposed deadline only after the caller rechecks current
/// authority, revocation, membership and worker/writer identity.
#[expect(
    clippy::too_many_arguments,
    reason = "This internal API keeps distinct contract fields explicit and does not itself grant authority."
)]
pub(super) fn proposed_permit(
    now: u64,
    current_safe_until: u64,
    mandate_max_until: u64,
    lease_intent: u64,
    window: u64,
    authority_observed_at: u64,
    freshness: u64,
    closing: bool,
) -> Result<u64, &'static str> {
    if closing || current_safe_until <= now || authority_observed_at > now {
        return Err("deadline_elapsed");
    }
    let window_end = now.checked_add(window).ok_or("deadline_elapsed")?;
    let freshness_end = authority_observed_at
        .checked_add(freshness)
        .ok_or("deadline_elapsed")?;
    let deadline = mandate_max_until
        .min(lease_intent)
        .min(window_end)
        .min(freshness_end);
    if deadline <= now || deadline > i64::MAX as u64 {
        return Err("deadline_elapsed");
    }
    Ok(deadline)
}

/// An already provisioned synthetic authority record, never a bearer issuer.
#[derive(Clone)]
pub(super) struct AuthorityGrant<'a> {
    pub(super) id: &'a str,
    pub(super) parent: Option<&'a str>,
    pub(super) tenant: &'a str,
    pub(super) project: &'a str,
    pub(super) actor: &'a str,
    pub(super) bearer_digest: [u8; 32],
    pub(super) scopes: u64,
    pub(super) can_delegate: bool,
    pub(super) enabled: bool,
    pub(super) member: bool,
    pub(super) revoked: bool,
    pub(super) not_before: u64,
    pub(super) access_expires: u64,
    pub(super) run_until: u64,
    pub(super) execution_ceiling: u64,
    pub(super) audience: &'a str,
}

#[derive(Debug, PartialEq)]
pub(super) struct Authenticated<'a> {
    pub(super) actor: &'a str,
    pub(super) initiator: &'a str,
    pub(super) lineage: Vec<&'a str>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "This internal API keeps distinct contract fields explicit and does not itself grant authority."
)]
pub(super) fn authenticate<'a>(
    records: &'a [AuthorityGrant<'a>],
    bearer: &[u8],
    tenant: &str,
    project: &str,
    required_scope: u64,
    now: u64,
    observed_at: u64,
    freshness: u64,
) -> Result<Authenticated<'a>, &'static str> {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    if !(32..=256).contains(&bearer.len())
        || records.is_empty()
        || records.len() > 128
        || required_scope == 0
    {
        return Err("auth_invalid");
    }
    let digest: [u8; 32] = Sha256::digest(bearer).into();
    let mut matching = records
        .iter()
        .filter(|record| bool::from(record.bearer_digest.ct_eq(&digest)));
    let mut current = matching.next().ok_or("auth_invalid")?;
    if matching.next().is_some() {
        return Err("auth_invalid");
    }
    // Credential IDs are persistent lineage identities. Ambiguous IDs cannot
    // be treated as a valid chain even when their bearer digests differ.
    if records.iter().enumerate().any(|(index, record)| {
        !(16..=128).contains(&record.id.len())
            || !record
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || records[..index]
                .iter()
                .any(|previous| previous.id == record.id)
    }) {
        return Err("delegation_denied");
    }
    let mut reverse = Vec::with_capacity(3);
    let mut scope_allowed = true;
    loop {
        if reverse.len() == 3
            || reverse
                .iter()
                .any(|old: &&AuthorityGrant<'_>| old.id == current.id)
        {
            return Err("delegation_denied");
        }
        if current.tenant != tenant
            || current.project != project
            || current.audience != "diffuser"
            || !current.enabled
            || !current.member
            || current.revoked
            || now < current.not_before
            || now >= current.access_expires
            || current.run_until == 0
            || current.execution_ceiling == 0
            || current.run_until > i64::MAX as u64
            || current.execution_ceiling > i64::MAX as u64
        {
            return Err("auth_invalid");
        }
        scope_allowed &= current.scopes & required_scope == required_scope;
        reverse.push(current);
        let Some(parent_id) = current.parent else {
            break;
        };
        let mut parents = records.iter().filter(|record| record.id == parent_id);
        let parent = parents.next().ok_or("delegation_denied")?;
        if parents.next().is_some()
            || !parent.can_delegate
            || current.scopes & !parent.scopes != 0
            || current.not_before < parent.not_before
            || current.access_expires > parent.access_expires
            || current.run_until > parent.run_until
            || current.run_until > parent.execution_ceiling
            || current.execution_ceiling > parent.execution_ceiling
        {
            return Err("delegation_denied");
        }
        current = parent;
    }
    if observed_at > now
        || observed_at
            .checked_add(freshness)
            .is_none_or(|end| now >= end)
    {
        return Err("evidence_stale");
    }
    if !scope_allowed {
        return Err("scope_denied");
    }
    reverse.reverse();
    Ok(Authenticated {
        actor: reverse.last().ok_or("auth_invalid")?.actor,
        initiator: reverse.first().ok_or("auth_invalid")?.actor,
        lineage: reverse.iter().map(|grant| grant.id).collect(),
    })
}

/// Injected authority records hold digests only; they never issue credentials.
#[derive(Clone)]
pub(super) struct OwnedAuthorityGrant {
    pub(super) id: String,
    pub(super) parent: Option<String>,
    pub(super) tenant: String,
    pub(super) project: String,
    pub(super) actor: String,
    pub(super) bearer_digest: [u8; 32],
    pub(super) scopes: u64,
    pub(super) can_delegate: bool,
    pub(super) enabled: bool,
    pub(super) member: bool,
    pub(super) revoked: bool,
    pub(super) not_before: u64,
    pub(super) access_expires: u64,
    pub(super) run_until: u64,
    pub(super) execution_ceiling: u64,
    pub(super) audience: String,
}

impl OwnedAuthorityGrant {
    pub(super) fn borrowed(&self) -> AuthorityGrant<'_> {
        AuthorityGrant {
            id: &self.id,
            parent: self.parent.as_deref(),
            tenant: &self.tenant,
            project: &self.project,
            actor: &self.actor,
            bearer_digest: self.bearer_digest,
            scopes: self.scopes,
            can_delegate: self.can_delegate,
            enabled: self.enabled,
            member: self.member,
            revoked: self.revoked,
            not_before: self.not_before,
            access_expires: self.access_expires,
            run_until: self.run_until,
            execution_ceiling: self.execution_ceiling,
            audience: &self.audience,
        }
    }
}
