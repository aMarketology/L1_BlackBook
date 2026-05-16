// Webhook handlers loaded at the binary crate root so they can access AppState.
// Actual implementation lives in contracts::deposit_webhook.
pub use crate::contracts::deposit_webhook::{helius_webhook_handler, alchemy_webhook_handler};
