//! # soothsay
//!
//! Read the omens before you `curl | sh`.
//!
//! `soothsay` statically reads a shell script, usually an installer you're
//! about to pipe into your shell, and explains what it will do to your machine:
//! which files it writes, which shell profiles it edits, whether it uses
//! `sudo`, installs startup items, downloads and runs *more* code, decodes
//! hidden payloads, or reaches for your SSH keys.
//!
//! ```
//! let report = soothsay::analyze("echo 'export PATH=$HOME/.tool/bin:$PATH' >> ~/.zshrc\n");
//! let f = &report.findings[0];
//! assert_eq!(f.category, soothsay::Category::ShellProfile);
//! assert_eq!(f.message, "appends to ~/.zshrc");
//! ```
//!
//! It is advisory static analysis, not a sandbox: anything the script
//! downloads and runs is listed as a *blind spot* rather than guessed at.

pub mod analyze;
pub mod diff;
pub mod guard;
pub mod json;
pub mod lexer;
pub mod parse;
pub mod render;
pub mod sha256;

pub use analyze::{analyze, Category, FileTouch, Finding, Report, Severity, Touch, Url};

/// Like [`analyze`], but for raw bytes: invalid UTF-8 is replaced for the
/// analysis, while `sha256` is the hash of the bytes exactly as given (what a
/// shell would run), not of the decoded text.
///
/// ```
/// let r = soothsay::analyze_bytes(b"echo \xff\n");
/// assert_eq!(r.sha256, soothsay::sha256::hex(b"echo \xff\n"));
/// ```
pub fn analyze_bytes(bytes: &[u8]) -> Report {
    let mut report = analyze(&String::from_utf8_lossy(bytes));
    report.sha256 = sha256::hex(bytes);
    report
}
