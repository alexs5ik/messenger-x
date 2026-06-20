//! Pre-key bundles for asynchronous session establishment (X3DH / PQXDH). A device
//! publishes a bundle to the server; a peer fetches it to start an encrypted session
//! without the recipient being online. The server stores these but cannot derive the
//! resulting session secret.

use serde::{Deserialize, Serialize};

use crate::crypto_material::{PublicKey, Signature};
use crate::ids::DeviceId;

/// A signed pre-key: a medium-term key signed by the device's long-term identity key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPreKey {
    pub key: PublicKey,
    /// Signature over `key` by the identity key.
    pub signature: Signature,
}

/// The full bundle a peer needs to run a PQXDH handshake against an offline device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub device_id: DeviceId,
    /// Long-term identity public key.
    pub identity_key: PublicKey,
    /// Medium-term signed pre-key (classical).
    pub signed_prekey: SignedPreKey,
    /// Optional one-time pre-key (classical), consumed per handshake when available.
    pub one_time_prekey: Option<PublicKey>,
    /// Post-quantum KEM pre-key (ML-KEM), the PQXDH addition to classical X3DH.
    pub pq_kem_prekey: SignedPreKey,
}
