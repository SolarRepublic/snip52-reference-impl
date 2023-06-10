use hkdf::hmac::Hmac;
use sha2::Sha256;

// Create alias for HMAC-SHA256
pub type HmacSha256 = Hmac<Sha256>;