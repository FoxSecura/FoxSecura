// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Mode lent automatique (V1) : rafale par salon, tous auteurs confondus
//! (12 messages en 7 s), évaluée avant la liste blanche (c'est un réglage du
//! salon, pas une sanction) ; le message continue ensuite dans la chaîne.
//!
//! - [`AutoSlowmodeDetector`] : rafales par salon (bornées) ;
//! - [`plan`] : pose (10 s, jamais réduire, jamais pendant un verrouillage),
//!   levée 90 s après le dernier déclenchement, nouvelle tentative toutes les
//!   30 s, restauration seulement si le salon porte encore le mode lent posé ;
//! - [`incident`] : incident `warning` à la pose.
//!
//! L'ancien mode lent est enregistré en base **avant** la pose (migration
//! 11) : la levée reprend après un redémarrage. Les rafales vivent dans le
//! processus (mono-instance).

mod detector;
pub mod incident;
pub mod plan;

pub use detector::{AutoSlowmodeDetector, AutoSlowmodeResult};
pub use incident::{
    AUTO_SLOWMODE_AUDIT_LABEL, SlowmodeIncidentInput, auto_slowmode_audit_reason,
    auto_slowmode_restore_reason, slowmode_incident,
};
pub use plan::{
    AUTO_SLOWMODE_LIFT_DELAY, AUTO_SLOWMODE_RETRY_INTERVAL, AUTO_SLOWMODE_SECONDS,
    AUTO_SLOWMODE_THRESHOLD, AUTO_SLOWMODE_WINDOW, AutoSlowmode, SlowmodeChannel, SlowmodeLift,
    SlowmodePlan, SlowmodeSkip, due_rows, lift_deadline, plan_slowmode, plan_slowmode_lift,
    retry_deadline,
};
