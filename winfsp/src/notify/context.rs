use crate::filesystem::FileSystemContext;
use crate::notify::Notifier;

/// A filesystem that supports operating system notifications.
pub trait NotifyingFileSystemContext<R>: FileSystemContext {
    /// Calculate a sentinel or context value if the filesystem is ready to notify the
    /// operating system, or return None if the filesystem is not ready.
    fn should_notify(&self) -> Option<R>;

    /// Publish the notification with the given sentinel or context value to the
    /// operating system.
    fn notify(&self, context: R, notifier: &Notifier);
}
