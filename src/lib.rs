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
pub mod lexer;
pub mod parse;
pub mod render;
pub mod sha256;

pub use analyze::{analyze, Category, FileTouch, Finding, Report, Severity, Touch, Url};
