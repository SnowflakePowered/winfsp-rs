//! NTFS-flavored wide-path types.
//!
//! [`NtfsPath`] / [`NtfsPathBuf`] are thin newtype wrappers over
//! [`U16CStr`] / [`U16CString`]: every path stored or returned through these
//! types is NUL-terminated, so it can be handed straight to WinFSP /
//! Win32 APIs that expect a `PWSTR`.
//!
//! ## Components
//!
//! Iteration uses the [`Components`] iterator (yielding [`NtfsComponent`]).
//! Two separator classes are recognised:
//!
//! * `\\` — directory separator (priority `2` in sort keys)
//! * `:`  — named-stream separator (priority `1` in sort keys)
//!
//! For `\foo\bar:s`, `components()` yields
//! `[Root, Normal("foo"), Normal("bar"), Stream("s")]`.
//!
//! ## Comparison
//!
//! Sort order matches memfs.cpp's `MemfsFileNameCompare`: runs of separators
//! collapse and contribute only the *kind* of the last separator, named
//! streams (`:`, priority `1`) sort before child directories (`\\`, priority
//! `2`), and case-insensitive mode upper-cases ASCII letters.
//! Non-ASCII characters are NOT case-folded (matching the fast path in the
//! C reference).

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use widestring::{U16CStr, U16CString, U16Str, u16cstr};

/// The wide character value of `\`.
pub const BACKSLASH: u16 = b'\\' as u16;
/// The wide character value of `:`.
pub const COLON: u16 = b':' as u16;

/// Sort-key marker for a `\\` separator (or the root).
const SEP_KEY_BACKSLASH: u16 = 2;
/// Sort-key marker for a `:` separator.
const SEP_KEY_COLON: u16 = 1;

/// A borrowed, NUL-terminated NTFS path.
#[repr(transparent)]
pub struct NtfsPath(U16CStr);

/// An owned, NUL-terminated NTFS path.
#[repr(transparent)]
#[derive(Clone)]
pub struct NtfsPathBuf(U16CString);

/// One element of an NTFS path produced by [`Components`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsComponent<'a> {
    /// The leading `\` of an absolute path.
    Root,
    /// A directory or file name component (text between two separators).
    Normal(&'a U16Str),
    /// A named-stream name (text after the first `:`).
    Stream(&'a U16Str),
}

impl<'a> NtfsComponent<'a> {
    /// The component's text content (empty for `Root`).
    pub fn name(&self) -> &'a U16Str {
        match self {
            NtfsComponent::Root => U16Str::from_slice(&[]),
            NtfsComponent::Normal(s) | NtfsComponent::Stream(s) => s,
        }
    }
}

// ---------------------------------------------------------------------------
// NtfsPath
// ---------------------------------------------------------------------------

impl NtfsPath {
    /// Wrap a `&U16CStr` as a `&NtfsPath`. Free — the layouts are identical.
    pub fn from_u16cstr(s: &U16CStr) -> &Self {
        // SAFETY: `NtfsPath` is `repr(transparent)` over `U16CStr`.
        unsafe { &*(s as *const U16CStr as *const Self) }
    }

    /// The shared root path `\`.
    pub fn root() -> &'static Self {
        Self::from_u16cstr(u16cstr!("\\"))
    }

    /// Returns the underlying NUL-terminated wide string view.
    pub fn as_u16cstr(&self) -> &U16CStr {
        &self.0
    }

    /// Returns the path's characters *without* the trailing NUL.
    pub fn as_ustr(&self) -> &U16Str {
        U16Str::from_slice(self.0.as_slice())
    }

    /// Returns the path's characters *without* the trailing NUL.
    pub fn as_slice(&self) -> &[u16] {
        self.0.as_slice()
    }

    /// Number of `u16`s in the path (excluding the trailing NUL).
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// True iff the path has no characters.
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    /// True iff this path is exactly `\`.
    pub fn is_root(&self) -> bool {
        self.as_slice() == [BACKSLASH]
    }

    /// Iterate the components of the path. See module docs for the shape.
    pub fn components(&self) -> Components<'_> {
        Components::new(self.as_slice())
    }

    /// Splits the path at the *last* `\` separator and returns the parent
    /// directory and the basename (which keeps any named-stream suffix).
    ///
    /// Mirrors `FspPathSuffix`: only `\` is treated as a separator. For a
    /// top-level path like `\foo`, the returned parent is `\` (the root).
    pub fn parent_and_basename(&self) -> (&U16Str, &U16Str) {
        let slice = self.as_slice();
        let mut last: Option<usize> = None;
        for (i, &c) in slice.iter().enumerate() {
            if c == BACKSLASH {
                last = Some(i);
            }
        }
        match last {
            Some(0) => (
                U16Str::from_slice(&slice[..1]),
                U16Str::from_slice(&slice[1..]),
            ),
            Some(i) => (
                U16Str::from_slice(&slice[..i]),
                U16Str::from_slice(&slice[i + 1..]),
            ),
            None => (U16Str::from_slice(&[BACKSLASH]), U16Str::from_slice(slice)),
        }
    }

    /// Returns the offset of the first `:`, if any.
    pub fn stream_index(&self) -> Option<usize> {
        self.as_slice().iter().position(|&c| c == COLON)
    }

    /// Returns the named-stream component (the part after `:`) if present.
    pub fn stream_name(&self) -> Option<&U16Str> {
        self.stream_index()
            .map(|i| U16Str::from_slice(&self.as_slice()[i + 1..]))
    }

    /// Returns this path with any named-stream suffix removed; if there is no
    /// `:`, the entire path is returned. Result is a borrowed slice (no NUL).
    pub fn main_slice(&self) -> &U16Str {
        match self.stream_index() {
            Some(i) => U16Str::from_slice(&self.as_slice()[..i]),
            None => self.as_ustr(),
        }
    }

    /// True iff `prefix` is a path-component prefix of `self`.
    ///
    /// Mirrors `MemfsFileNameHasPrefix`: the match must extend up to a `\`,
    /// `:`, or the end of `self`. `\` (the root) is a prefix of everything.
    pub fn has_prefix(&self, prefix: &Self, case_insensitive: bool) -> bool {
        let a = self.canonical_key(case_insensitive);
        let p = prefix.canonical_key(case_insensitive);
        canonical_starts_with(a.as_slice(), p.as_slice())
    }

    /// Compares two paths under `MemfsFileNameCompare` semantics.
    pub fn compare(&self, other: &Self, case_insensitive: bool) -> Ordering {
        let a = self.canonical_key(case_insensitive);
        let b = other.canonical_key(case_insensitive);
        a.cmp(&b)
    }

    /// Compute the lookup key used to order paths inside the file-node map.
    /// Two paths that are equal under [`compare`](Self::compare) produce the
    /// same canonical key; any path-aware sort using these keys preserves the
    /// memfs ordering invariants (named streams sort before child entries,
    /// etc.).
    ///
    /// The returned [`NtfsPathBuf`] holds the canonical-form bytes (with
    /// separator markers `1`/`2` standing in for `:`/`\`); its bytewise `Ord`
    /// gives the path-aware ordering directly.
    pub fn canonical_key(&self, case_insensitive: bool) -> NtfsPathBuf {
        let mut out = Vec::with_capacity(self.len() + 1);
        let mut saw_root = false;
        let mut emitted_body = false;
        for comp in self.components() {
            match comp {
                NtfsComponent::Root => {
                    saw_root = true;
                }
                NtfsComponent::Normal(s) => {
                    if saw_root || emitted_body {
                        out.push(SEP_KEY_BACKSLASH);
                    }
                    push_folded(&mut out, s, case_insensitive);
                    emitted_body = true;
                    saw_root = false;
                }
                NtfsComponent::Stream(s) => {
                    if saw_root && !emitted_body {
                        out.push(SEP_KEY_BACKSLASH);
                    }
                    out.push(SEP_KEY_COLON);
                    push_folded(&mut out, s, case_insensitive);
                    emitted_body = true;
                    saw_root = false;
                }
            }
        }
        if saw_root {
            out.push(SEP_KEY_BACKSLASH);
        }
        // Canonical bytes never contain NUL: separator markers are 1/2, and
        // the source path is a NUL-terminated U16CStr (no interior NUL).
        NtfsPathBuf(U16CString::from_vec(out).expect("canonical key contains no NUL"))
    }
}

impl std::fmt::Debug for NtfsPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl PartialEq for NtfsPath {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for NtfsPath {}

impl PartialOrd for NtfsPath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Bytewise ordering. For path-aware comparison use [`NtfsPath::compare`]; the
/// two coincide for canonical-key paths produced by
/// [`canonical_key`](NtfsPath::canonical_key), which is what the memfs node
/// index relies on.
impl Ord for NtfsPath {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl Hash for NtfsPath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}

impl<'a> From<&'a U16CStr> for &'a NtfsPath {
    fn from(s: &'a U16CStr) -> Self {
        NtfsPath::from_u16cstr(s)
    }
}

impl AsRef<NtfsPath> for NtfsPath {
    fn as_ref(&self) -> &NtfsPath {
        self
    }
}

impl AsRef<U16CStr> for NtfsPath {
    fn as_ref(&self) -> &U16CStr {
        &self.0
    }
}

impl ToOwned for NtfsPath {
    type Owned = NtfsPathBuf;

    fn to_owned(&self) -> NtfsPathBuf {
        NtfsPathBuf(self.0.to_owned())
    }
}

// ---------------------------------------------------------------------------
// NtfsPathBuf
// ---------------------------------------------------------------------------

impl NtfsPathBuf {
    /// Build an [`NtfsPathBuf`] that contains just the root `\`.
    pub fn root() -> Self {
        Self(u16cstr!("\\").to_owned())
    }

    /// Build an [`NtfsPathBuf`] from a raw, NUL-free wide-character slice.
    ///
    /// Returns `None` if the slice contains an interior NUL.
    pub fn from_slice(slice: &[u16]) -> Option<Self> {
        U16CString::from_vec(slice.to_vec()).ok().map(Self)
    }

    /// Build an [`NtfsPathBuf`] from a NUL-terminated wide string.
    pub fn from_u16cstr(s: &U16CStr) -> Self {
        Self(s.to_owned())
    }

    /// Borrow as a `&NtfsPath`.
    pub fn as_path(&self) -> &NtfsPath {
        NtfsPath::from_u16cstr(self.0.as_ucstr())
    }

    /// Consume `self`, returning the underlying [`U16CString`].
    pub fn into_inner(self) -> U16CString {
        self.0
    }

    /// Borrow as a NUL-terminated wide string view.
    pub fn as_u16cstr(&self) -> &U16CStr {
        self.0.as_ucstr()
    }

    /// Join a child component (a single basename, optionally with a `:stream`
    /// suffix) onto this path with a `\` separator.
    ///
    /// If `self` is the root `\`, no extra separator is inserted. Returns
    /// `None` if `child` contains an interior NUL.
    pub fn join(&self, child: &U16Str) -> Option<Self> {
        let parent = self.as_slice();
        let child = child.as_slice();
        let mut buf = Vec::with_capacity(parent.len() + 1 + child.len());
        buf.extend_from_slice(parent);
        if !(parent.len() == 1 && parent[0] == BACKSLASH) {
            buf.push(BACKSLASH);
        }
        buf.extend_from_slice(child);
        U16CString::from_vec(buf).ok().map(Self)
    }

    /// Builds a fresh `NtfsPathBuf` by joining `parent` and `child` with a
    /// `\` separator. Equivalent to wrapping `parent` in an `NtfsPathBuf`
    /// transiently and calling [`join`](Self::join).
    pub fn join_slices(parent: &U16Str, child: &U16Str) -> Option<Self> {
        let parent = parent.as_slice();
        let child = child.as_slice();
        let mut buf = Vec::with_capacity(parent.len() + 1 + child.len());
        buf.extend_from_slice(parent);
        if !(parent.len() == 1 && parent[0] == BACKSLASH) {
            buf.push(BACKSLASH);
        }
        buf.extend_from_slice(child);
        U16CString::from_vec(buf).ok().map(Self)
    }
}

impl Default for NtfsPathBuf {
    fn default() -> Self {
        Self::root()
    }
}

impl std::fmt::Debug for NtfsPathBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl Deref for NtfsPathBuf {
    type Target = NtfsPath;

    fn deref(&self) -> &NtfsPath {
        self.as_path()
    }
}

impl Borrow<NtfsPath> for NtfsPathBuf {
    fn borrow(&self) -> &NtfsPath {
        self.as_path()
    }
}

impl AsRef<NtfsPath> for NtfsPathBuf {
    fn as_ref(&self) -> &NtfsPath {
        self.as_path()
    }
}

impl AsRef<U16CStr> for NtfsPathBuf {
    fn as_ref(&self) -> &U16CStr {
        self.0.as_ucstr()
    }
}

impl PartialEq for NtfsPathBuf {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for NtfsPathBuf {}

impl PartialOrd for NtfsPathBuf {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NtfsPathBuf {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_path().cmp(other.as_path())
    }
}

impl From<&NtfsPath> for NtfsPathBuf {
    fn from(p: &NtfsPath) -> Self {
        p.to_owned()
    }
}

impl From<&U16CStr> for NtfsPathBuf {
    fn from(s: &U16CStr) -> Self {
        Self::from_u16cstr(s)
    }
}

// ---------------------------------------------------------------------------
// Components iterator
// ---------------------------------------------------------------------------

/// Iterator over the [`NtfsComponent`]s of a [`NtfsPath`].
#[derive(Clone)]
pub struct Components<'a> {
    slice: &'a [u16],
    pos: usize,
    state: CompState,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum CompState {
    Start,
    Body,
    Stream,
    Done,
}

impl<'a> Components<'a> {
    fn new(slice: &'a [u16]) -> Self {
        Self {
            slice,
            pos: 0,
            state: CompState::Start,
        }
    }

    /// Returns the un-consumed path tail as a `&U16Str`.
    pub fn remainder(&self) -> &'a U16Str {
        U16Str::from_slice(&self.slice[self.pos..])
    }
}

impl<'a> Iterator for Components<'a> {
    type Item = NtfsComponent<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.state {
                CompState::Start => {
                    if self.slice.first() == Some(&BACKSLASH) {
                        self.pos = 1;
                        self.state = CompState::Body;
                        return Some(NtfsComponent::Root);
                    }
                    self.state = CompState::Body;
                }
                CompState::Body => {
                    // Collapse runs of empty components (`\\`).
                    while self.pos < self.slice.len() && self.slice[self.pos] == BACKSLASH {
                        self.pos += 1;
                    }
                    if self.pos >= self.slice.len() {
                        self.state = CompState::Done;
                        return None;
                    }
                    let start = self.pos;
                    while self.pos < self.slice.len() {
                        match self.slice[self.pos] {
                            BACKSLASH => {
                                let comp = &self.slice[start..self.pos];
                                self.pos += 1;
                                if comp.is_empty() {
                                    break;
                                }
                                return Some(NtfsComponent::Normal(U16Str::from_slice(comp)));
                            }
                            COLON => {
                                let comp = &self.slice[start..self.pos];
                                self.pos += 1;
                                self.state = CompState::Stream;
                                if !comp.is_empty() {
                                    return Some(NtfsComponent::Normal(U16Str::from_slice(comp)));
                                }
                                let stream = &self.slice[self.pos..];
                                self.pos = self.slice.len();
                                self.state = CompState::Done;
                                return Some(NtfsComponent::Stream(U16Str::from_slice(stream)));
                            }
                            _ => {
                                self.pos += 1;
                            }
                        }
                    }
                    let comp = &self.slice[start..self.pos];
                    self.state = CompState::Done;
                    if !comp.is_empty() {
                        return Some(NtfsComponent::Normal(U16Str::from_slice(comp)));
                    }
                    return None;
                }
                CompState::Stream => {
                    let comp = &self.slice[self.pos..];
                    self.pos = self.slice.len();
                    self.state = CompState::Done;
                    return Some(NtfsComponent::Stream(U16Str::from_slice(comp)));
                }
                CompState::Done => return None,
            }
        }
    }
}

impl std::iter::FusedIterator for Components<'_> {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[inline]
fn fold_char(c: u16, case_insensitive: bool) -> u16 {
    if case_insensitive && (b'a' as u16..=b'z' as u16).contains(&c) {
        c - (b'a' as u16 - b'A' as u16)
    } else {
        c
    }
}

#[inline]
fn push_folded(out: &mut Vec<u16>, s: &U16Str, case_insensitive: bool) {
    out.extend(s.as_slice().iter().map(|&c| fold_char(c, case_insensitive)));
}

/// Path-aware `starts_with` over canonical keys. The match must end either at
/// the end of `a`, immediately before a separator marker in `a`, or `b` must
/// be the bare root key.
fn canonical_starts_with(a: &[u16], b: &[u16]) -> bool {
    if a.len() < b.len() {
        return false;
    }
    if !a.starts_with(b) {
        return false;
    }
    if a.len() == b.len() {
        return true;
    }
    if b == [SEP_KEY_BACKSLASH] {
        return true;
    }
    matches!(a[b.len()], SEP_KEY_BACKSLASH | SEP_KEY_COLON)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> NtfsPathBuf {
        NtfsPathBuf::from_slice(&s.encode_utf16().collect::<Vec<_>>()).unwrap()
    }

    fn ws(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn components_root() {
        let path = p("\\");
        let comps: Vec<_> = path.components().collect();
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0], NtfsComponent::Root);
    }

    #[test]
    fn components_absolute() {
        let path = p("\\foo\\bar");
        let comps: Vec<_> = path.components().collect();
        assert_eq!(comps.len(), 3);
        assert_eq!(comps[0], NtfsComponent::Root);
        assert!(matches!(comps[1], NtfsComponent::Normal(s) if s.as_slice() == ws("foo")));
        assert!(matches!(comps[2], NtfsComponent::Normal(s) if s.as_slice() == ws("bar")));
    }

    #[test]
    fn components_stream() {
        let path = p("\\foo:stream");
        let comps: Vec<_> = path.components().collect();
        assert_eq!(comps.len(), 3);
        assert_eq!(comps[0], NtfsComponent::Root);
        assert!(matches!(comps[1], NtfsComponent::Normal(s) if s.as_slice() == ws("foo")));
        assert!(matches!(comps[2], NtfsComponent::Stream(s) if s.as_slice() == ws("stream")));
    }

    #[test]
    fn components_collapse_doubled_backslash() {
        let path = p("\\\\foo");
        let comps: Vec<_> = path.components().collect();
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[0], NtfsComponent::Root);
        assert!(matches!(comps[1], NtfsComponent::Normal(s) if s.as_slice() == ws("foo")));
    }

    #[test]
    fn canonical_root() {
        assert_eq!(p("\\").canonical_key(false).as_slice(), &[SEP_KEY_BACKSLASH]);
    }

    #[test]
    fn canonical_orders_streams_before_children() {
        let stream = p("\\foo:s").canonical_key(false);
        let child = p("\\foo\\b").canonical_key(false);
        assert!(stream < child);
    }

    #[test]
    fn canonical_case_insensitive() {
        let a = p("\\Foo").canonical_key(true);
        let b = p("\\FOO").canonical_key(true);
        assert_eq!(a, b);
        let c = p("\\Foo").canonical_key(false);
        let d = p("\\FOO").canonical_key(false);
        assert_ne!(c, d);
    }

    #[test]
    fn parent_basename() {
        let path = p("\\foo\\bar");
        let (parent, base) = path.parent_and_basename();
        assert_eq!(parent.as_slice(), ws("\\foo"));
        assert_eq!(base.as_slice(), ws("bar"));

        let top = p("\\bar");
        let (parent, base) = top.parent_and_basename();
        assert_eq!(parent.as_slice(), &[BACKSLASH]);
        assert_eq!(base.as_slice(), ws("bar"));

        let stream = p("\\foo:s");
        let (parent, base) = stream.parent_and_basename();
        assert_eq!(parent.as_slice(), &[BACKSLASH]);
        assert_eq!(base.as_slice(), ws("foo:s"));
    }

    #[test]
    fn has_prefix_path_component_aware() {
        assert!(p("\\foo\\bar").has_prefix(&p("\\foo"), false));
        assert!(p("\\foo:s").has_prefix(&p("\\foo"), false));
        assert!(!p("\\fooxxx").has_prefix(&p("\\foo"), false));
        assert!(p("\\foo").has_prefix(&p("\\"), false));
        assert!(p("\\Foo").has_prefix(&p("\\FOO"), true));
        assert!(!p("\\Foo").has_prefix(&p("\\FOO"), false));
    }

    #[test]
    fn join_collapses_root() {
        let parent = NtfsPathBuf::root();
        let joined = parent
            .join(U16Str::from_slice(&ws("foo")))
            .expect("join must succeed");
        assert_eq!(joined.as_slice(), ws("\\foo"));

        let joined = NtfsPathBuf::join_slices(
            U16Str::from_slice(&ws("\\foo")),
            U16Str::from_slice(&ws("bar")),
        )
        .unwrap();
        assert_eq!(joined.as_slice(), ws("\\foo\\bar"));
    }

    #[test]
    fn stream_name_extraction() {
        assert!(p("\\foo").stream_name().is_none());
        assert_eq!(p("\\foo:bar").stream_name().unwrap().as_slice(), ws("bar"),);
        assert_eq!(p("\\foo:bar").main_slice().as_slice(), ws("\\foo"));
    }

    #[test]
    fn compare_orders_like_memfs_cpp() {
        let cases = [
            ("\\", "\\a", Ordering::Less),
            ("\\a:s", "\\a\\b", Ordering::Less),
            ("\\a", "\\a\\b", Ordering::Less),
            ("\\b", "\\a", Ordering::Greater),
        ];
        for (a, b, expected) in cases {
            assert_eq!(p(a).compare(&p(b), false), expected, "{a} vs {b}");
        }
    }
}
