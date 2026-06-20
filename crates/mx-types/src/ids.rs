//! Strongly-typed identifiers. Newtypes over [`Uuid`] so a `UserId` can never be passed
//! where a `GroupId` is expected.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! uuid_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Allocate a fresh random id.
            #[inline]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<Uuid> for $name {
            fn from(u: Uuid) -> Self {
                Self(u)
            }
        }
    };
}

uuid_id!(
    /// Identifies a human account.
    UserId
);
uuid_id!(
    /// Identifies a single device/installation belonging to a user. Crypto sessions are
    /// per-device (multi-device fan-out), following the Signal model.
    DeviceId
);
uuid_id!(
    /// Identifies a group / community / channel.
    GroupId
);
uuid_id!(
    /// Identifies a single message.
    MessageId
);
uuid_id!(
    /// Identifies a pairwise crypto session between two devices.
    SessionId
);
