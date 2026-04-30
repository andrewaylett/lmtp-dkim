use crate::{EmailAddress, ReversePath};

/// Owned version of [`ReversePath`] for storage in session state.
#[expect(clippy::exhaustive_enums, reason = "Genuinely exhaustive")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedReversePath {
    /// A real sender address.
    Address(EmailAddress),
    /// The null path `<>`.
    Null,
}

impl std::fmt::Display for OwnedReversePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r: ReversePath = self.into();
        r.fmt(f)
    }
}
