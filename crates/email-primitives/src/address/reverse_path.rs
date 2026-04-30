use crate::{EmailAddress, OwnedReversePath};

/// The reverse-path used in `MAIL FROM` (RFC 5321 section 4.1.1.2).
///
/// The reverse-path is either a real address or the null path `<>`, which
/// is used for bounce messages so that bounces cannot themselves bounce
/// (RFC 5321 section 4.5.5).
#[expect(clippy::exhaustive_enums, reason = "Genuinely exhaustive")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReversePath<'a> {
    /// A real sender address.
    Address(&'a EmailAddress),
    /// The null path `<>` for bounces and delivery status notifications.
    Null,
}

impl<'a> From<&'a OwnedReversePath> for ReversePath<'a> {
    fn from(value: &'a OwnedReversePath) -> Self {
        match value {
            OwnedReversePath::Address(addr) => ReversePath::Address(addr),
            OwnedReversePath::Null => ReversePath::Null,
        }
    }
}

impl std::fmt::Display for ReversePath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address(addr) => write!(f, "<{addr}>"),
            Self::Null => f.write_str("<>"),
        }
    }
}
