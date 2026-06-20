//! mx-ai — the tiered AI orchestrator that enforces Messenger X's **envelope rule**
//! (design doc §8).
//!
//! ## The envelope rule
//!
//! Plaintext message content may be processed by AI **only**:
//! 1. **on the user's own device** ([`Tier::OnDevice`]),
//! 2. **inside an attested confidential enclave** ([`Tier::ConfidentialEnclave`]), or
//! 3. **by an external frontier model** ([`Tier::ExternalFrontier`]) — *and only* with the
//!    user's **explicit, informed consent**.
//!
//! The backend stores and routes ciphertext only; any time plaintext is handled, exactly one
//! of those three conditions must hold. The [`AiOrchestrator`] is the choke point that makes
//! the rule mechanical rather than a matter of discipline: it picks the **lowest tier able to
//! serve** a request and refuses to leak E2E-protected plaintext to an external model unless
//! the caller carries explicit consent.
//!
//! ```
//! use mx_ai::{AiOrchestrator, AiRequest, Sensitivity, Tier};
//!
//! # async fn demo() {
//! let orch = AiOrchestrator::with_mock_providers();
//!
//! // Routine, E2E-protected task -> stays on device.
//! let req = AiRequest::e2e("summarize this chat");
//! assert_eq!(orch.tier_for(&req).unwrap(), Tier::OnDevice);
//!
//! // E2E task that demands an external agent, but no consent given -> rejected.
//! let req = AiRequest::e2e("book me a flight").requiring(Tier::ExternalFrontier);
//! assert!(orch.route(&req).await.is_err());
//! # }
//! ```

use async_trait::async_trait;
use mx_types::{Error, Result};

/// Where AI inference is allowed to run, ordered from most private / cheapest to least private.
///
/// The numeric ordering (via `PartialOrd`/`Ord`) is meaningful: a *lower* tier is more private
/// and is always preferred when it can serve the request. Never reorder these variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// Tier 1 — small models running on the user's device. Plaintext never leaves the phone.
    /// Default for routine tasks (summaries, smart replies, translation, local search).
    OnDevice,
    /// Tier 2 — an attested TEE enclave (cf. Apple Private Cloud Compute). Plaintext exists
    /// only inside the enclave, verifiably. Used for heavy tasks (long documents, big-history RAG).
    ConfidentialEnclave,
    /// Tier 3 — an external frontier model (Claude/GPT via API). Data consciously leaves the
    /// security perimeter; permitted for E2E-protected content **only with explicit user consent**.
    ExternalFrontier,
}

impl Tier {
    /// All tiers, in privacy-preference order (most private first).
    pub const ALL: [Tier; 3] = [
        Tier::OnDevice,
        Tier::ConfidentialEnclave,
        Tier::ExternalFrontier,
    ];
}

/// Sensitivity classification of the data attached to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// The payload is (or derives from) end-to-end encrypted message content. The envelope rule
    /// applies in full: it may only leave the perimeter with explicit consent.
    E2EProtected,
    /// Non-sensitive / already-public data. May be handled by any tier without special consent.
    Public,
}

/// A unit of work submitted to the orchestrator.
#[derive(Debug, Clone)]
pub struct AiRequest {
    /// Free-form description of the task ("summarize this chat", "book a flight", …).
    pub task: String,
    /// Sensitivity of the data the task operates on.
    pub sensitivity: Sensitivity,
    /// Whether the user has given **explicit, informed consent** to send this request's data to
    /// an external frontier model. Meaningful only for [`Sensitivity::E2EProtected`] requests;
    /// public requests do not need it.
    pub user_consent_external: bool,
    /// Optional minimum tier the task *requires* to be served (e.g. a heavy task that an
    /// on-device model cannot handle). The orchestrator never routes below this floor.
    /// `None` means the task is routine and defaults to the most private tier.
    pub min_tier: Option<Tier>,
}

impl AiRequest {
    /// Construct a request explicitly.
    pub fn new(
        task: impl Into<String>,
        sensitivity: Sensitivity,
        user_consent_external: bool,
    ) -> Self {
        Self {
            task: task.into(),
            sensitivity,
            user_consent_external,
            min_tier: None,
        }
    }

    /// Convenience: an E2E-protected, routine task with no external consent.
    pub fn e2e(task: impl Into<String>) -> Self {
        Self::new(task, Sensitivity::E2EProtected, false)
    }

    /// Convenience: a public, routine task.
    pub fn public(task: impl Into<String>) -> Self {
        Self::new(task, Sensitivity::Public, false)
    }

    /// Builder-style: record that the user explicitly consented to external processing.
    #[must_use]
    pub fn with_external_consent(mut self) -> Self {
        self.user_consent_external = true;
        self
    }

    /// Builder-style: declare the minimum tier the task needs (its compute floor).
    #[must_use]
    pub fn requiring(mut self, min_tier: Tier) -> Self {
        self.min_tier = Some(min_tier);
        self
    }

    /// True if this request carries end-to-end-encrypted-derived plaintext.
    fn is_e2e(&self) -> bool {
        matches!(self.sensitivity, Sensitivity::E2EProtected)
    }
}

/// A backend capable of serving requests at a particular [`Tier`].
///
/// Implementations are responsible only for *doing the work*; the envelope-rule policy is
/// enforced upstream by the [`AiOrchestrator`], so a provider can assume that by the time
/// [`handle`](AiProvider::handle) is called the routing decision is already permitted.
#[async_trait]
pub trait AiProvider: Send + Sync {
    /// The tier this provider runs at.
    fn tier(&self) -> Tier;

    /// Process the request and return a (mock, here) textual result.
    async fn handle(&self, req: &AiRequest) -> String;
}

/// A trivial provider that simply echoes which tier handled the task. Stands in for a real
/// on-device model / enclave / frontier API while the rest of the system is built out.
pub struct MockProvider {
    tier: Tier,
}

impl MockProvider {
    /// Create a mock provider pinned to `tier`.
    pub fn new(tier: Tier) -> Self {
        Self { tier }
    }
}

#[async_trait]
impl AiProvider for MockProvider {
    fn tier(&self) -> Tier {
        self.tier
    }

    async fn handle(&self, req: &AiRequest) -> String {
        format!("[{:?}] handled task: {}", self.tier, req.task)
    }
}

/// Routes [`AiRequest`]s to the lowest-tier [`AiProvider`] that may serve them, enforcing the
/// envelope rule at the routing boundary.
pub struct AiOrchestrator {
    /// Providers, kept sorted ascending by tier so the most private capable one is found first.
    providers: Vec<Box<dyn AiProvider>>,
}

impl AiOrchestrator {
    /// Build an orchestrator from a set of providers. They are sorted into privacy-preference
    /// order internally, so caller order does not matter.
    pub fn new(mut providers: Vec<Box<dyn AiProvider>>) -> Self {
        providers.sort_by_key(|p| p.tier());
        Self { providers }
    }

    /// Build an orchestrator wired with one [`MockProvider`] per tier — handy for tests and for
    /// bootstrapping the system before real backends exist.
    pub fn with_mock_providers() -> Self {
        Self::new(
            Tier::ALL
                .iter()
                .map(|&t| Box::new(MockProvider::new(t)) as Box<dyn AiProvider>)
                .collect(),
        )
    }

    /// Decide which tier should serve `req`, applying the envelope rule, **without** running it.
    ///
    /// Policy:
    /// - Start from the request's compute floor (`min_tier`, default [`Tier::OnDevice`]) — routine
    ///   tasks therefore default to on-device.
    /// - Pick the lowest registered tier `>=` that floor (most private capable provider).
    /// - **Envelope enforcement:** an [`Sensitivity::E2EProtected`] request may never be served by
    ///   [`Tier::ExternalFrontier`] unless `user_consent_external` is set; otherwise this returns
    ///   [`Error::Unauthorized`].
    /// - If no provider can satisfy the floor, returns [`Error::InvalidInput`].
    pub fn tier_for(&self, req: &AiRequest) -> Result<Tier> {
        let floor = req.min_tier.unwrap_or(Tier::OnDevice);

        // Lowest available tier at or above the required floor (providers are pre-sorted).
        let chosen = self
            .providers
            .iter()
            .map(|p| p.tier())
            .find(|&t| t >= floor)
            .ok_or_else(|| {
                Error::InvalidInput(format!(
                    "no AI provider available at or above required tier {floor:?}"
                ))
            })?;

        // The envelope rule: E2E plaintext must not reach an external frontier model without
        // explicit, informed user consent.
        if chosen == Tier::ExternalFrontier && req.is_e2e() && !req.user_consent_external {
            return Err(Error::Unauthorized);
        }

        Ok(chosen)
    }

    /// Route and execute `req` on the selected provider, returning its output.
    ///
    /// Errors exactly as [`tier_for`](Self::tier_for) does (notably [`Error::Unauthorized`] when
    /// the envelope rule would be violated).
    pub async fn route(&self, req: &AiRequest) -> Result<String> {
        let tier = self.tier_for(req)?;
        let provider = self
            .providers
            .iter()
            .find(|p| p.tier() == tier)
            // tier_for only returns tiers that exist among providers, so this is unreachable.
            .ok_or_else(|| Error::Internal("selected tier has no provider".into()))?;
        Ok(provider.handle(req).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn orch() -> AiOrchestrator {
        AiOrchestrator::with_mock_providers()
    }

    #[tokio::test]
    async fn routine_e2e_task_defaults_to_on_device() {
        let req = AiRequest::e2e("summarize this chat");
        assert_eq!(orch().tier_for(&req).unwrap(), Tier::OnDevice);
        let out = orch().route(&req).await.unwrap();
        assert!(out.contains("OnDevice"), "got: {out}");
    }

    #[tokio::test]
    async fn public_routine_task_stays_on_device() {
        let req = AiRequest::public("translate a public FAQ");
        assert_eq!(orch().tier_for(&req).unwrap(), Tier::OnDevice);
    }

    #[tokio::test]
    async fn public_task_may_use_enclave_when_required() {
        // A heavy but public task is allowed in the enclave (no consent needed).
        let req =
            AiRequest::public("RAG over a public corpus").requiring(Tier::ConfidentialEnclave);
        assert_eq!(orch().tier_for(&req).unwrap(), Tier::ConfidentialEnclave);
    }

    #[tokio::test]
    async fn e2e_external_without_consent_is_rejected() {
        let req = AiRequest::e2e("book me a flight").requiring(Tier::ExternalFrontier);
        let err = orch().route(&req).await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized), "got: {err:?}");
    }

    #[tokio::test]
    async fn e2e_external_with_consent_is_allowed() {
        let req = AiRequest::e2e("book me a flight")
            .requiring(Tier::ExternalFrontier)
            .with_external_consent();
        assert_eq!(orch().tier_for(&req).unwrap(), Tier::ExternalFrontier);
        let out = orch().route(&req).await.unwrap();
        assert!(out.contains("ExternalFrontier"), "got: {out}");
    }

    #[tokio::test]
    async fn public_external_needs_no_consent() {
        // Public data may go external freely — the envelope rule only guards E2E plaintext.
        let req = AiRequest::public("search the public web").requiring(Tier::ExternalFrontier);
        assert_eq!(orch().tier_for(&req).unwrap(), Tier::ExternalFrontier);
    }

    #[tokio::test]
    async fn routing_precedence_picks_lowest_capable_tier() {
        // Floor at enclave: must not drop to on-device, must not climb to external.
        let req = AiRequest::e2e("heavy analysis").requiring(Tier::ConfidentialEnclave);
        assert_eq!(orch().tier_for(&req).unwrap(), Tier::ConfidentialEnclave);
    }

    #[tokio::test]
    async fn unsatisfiable_floor_errors() {
        // Orchestrator with only an on-device provider cannot satisfy an external-tier floor.
        let only_on_device =
            AiOrchestrator::new(vec![Box::new(MockProvider::new(Tier::OnDevice))]);
        let req = AiRequest::public("x").requiring(Tier::ExternalFrontier);
        assert!(matches!(
            only_on_device.tier_for(&req).unwrap_err(),
            Error::InvalidInput(_)
        ));
    }

    #[test]
    fn tier_ordering_is_privacy_first() {
        assert!(Tier::OnDevice < Tier::ConfidentialEnclave);
        assert!(Tier::ConfidentialEnclave < Tier::ExternalFrontier);
    }
}
