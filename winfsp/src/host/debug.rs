use crate::constants::FspTransactKind;

/// Debug output mask on file system transaction kinds.
#[derive(Debug, Copy, Clone)]
pub struct DebugMode(u32);

impl Default for DebugMode {
    fn default() -> Self {
        DebugMode::none()
    }
}

impl DebugMode {
    /// Disable all debug output.
    pub const fn none() -> Self {
        Self(0)
    }

    /// Enable debug output for all transaction kinds.
    pub const fn all() -> Self {
        Self(u32::MAX)
    }

    /// Enable debug output for the specific transaction kind.
    pub const fn enable_kind(self, kind: FspTransactKind) -> Self {
        Self(self.0 | (1 << kind as usize))
    }

    /// Disable debug output for the specific transaction kind.
    pub const fn disable_kind(self, kind: FspTransactKind) -> Self {
        Self(self.0 & !(1 << kind as usize))
    }
}

impl From<DebugMode> for u32 {
    fn from(d: DebugMode) -> Self {
        d.0
    }
}
