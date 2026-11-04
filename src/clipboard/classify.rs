//! Classification of a clipboard selection by its offered MIME types.
//!
//! The Wayland clipboard has no type registry: a selection is a set of
//! `(MIME string, bytes)` renditions negotiated between writer and reader.
//! This module turns the offer list into a decision for the sync layer.

use lamco_data_control::find_mime_match;

/// Password managers offer this marker next to the secret so that clipboard
/// history tools skip it (originated in KDE, honored ecosystem-wide).
const PASSWORD_HINT: &str = "x-kde-passwordManagerHint";

/// File-reference MIMEs, in read-priority order. The GNOME flavor wins
/// because it also encodes the copy/cut operation.
const FILE_REF_MIMES: [&str; 2] = ["x-special/gnome-copied-files", "text/uri-list"];

/// Image types that can travel through the clipboard as plain bytes,
/// best-quality first.
const PREFERRED_IMAGES: [&str; 5] = [
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/bmp",
    "image/tiff",
];

/// How a selection should be handled by the sync layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionKind {
    /// Secrets (password-manager hint): never sync, never even read.
    Sensitive,
    /// References to local files; `mimes` holds the offered reference types
    /// in read-priority order. The copy/cut state lives in the payload, see
    /// [`parse_file_refs`].
    Files { mimes: Vec<String> },
    /// An image rendition; the bytes can go through the clipboard as-is.
    Image { mime: String },
    /// HTML plus (usually) a plain-text fallback rendition of the same content.
    RichText { html: String, plain: Option<String> },
    /// Plain text only.
    PlainText { mime: String },
    /// Nothing recognized: sync every offered MIME verbatim instead of
    /// dropping it.
    Passthrough { mimes: Vec<String> },
}

/// Classify a selection by precedence: sensitive > file references > image >
/// rich text > plain text > passthrough.
///
/// Matching is on the *base* MIME type (the part before `;`), so e.g.
/// `text/html;charset=utf-8` counts as `text/html`. Plain-text matching also
/// tolerates charset differences via [`find_mime_match`].
#[must_use]
pub fn classify(mimes: &[String]) -> SelectionKind {
    if find_base(mimes, PASSWORD_HINT).is_some() {
        return SelectionKind::Sensitive;
    }

    let file_mimes: Vec<String> = FILE_REF_MIMES
        .iter()
        .filter_map(|base| find_base(mimes, base))
        .map(str::to_owned)
        .collect();
    if !file_mimes.is_empty() {
        return SelectionKind::Files { mimes: file_mimes };
    }

    if let Some(mime) = PREFERRED_IMAGES
        .iter()
        .find_map(|base| find_base(mimes, base))
    {
        return SelectionKind::Image {
            mime: mime.to_owned(),
        };
    }

    if let Some(mime) = mimes
        .iter()
        .map(String::as_str)
        .find(|m| m.starts_with("image/"))
    {
        return SelectionKind::Image {
            mime: mime.to_owned(),
        };
    }

    if let Some(html) = find_base(mimes, "text/html") {
        let plain = find_mime_match("text/plain;charset=utf-8", mimes).map(str::to_owned);
        return SelectionKind::RichText {
            html: html.to_owned(),
            plain,
        };
    }

    if let Some(plain) = find_mime_match("text/plain;charset=utf-8", mimes) {
        return SelectionKind::PlainText {
            mime: plain.to_owned(),
        };
    }

    SelectionKind::Passthrough {
        mimes: mimes.to_vec(),
    }
}

/// Parse the payload of a file-reference MIME into `(was_cut, uris)`.
///
/// - `x-special/gnome-copied-files`: first line is `copy` or `cut`, then one
///   URI per line.
/// - `text/uri-list` (RFC 2483): one URI per line, `#` lines are comments.
/// - Anything else: no references.
#[must_use]
pub fn parse_file_refs(mime: &str, bytes: &[u8]) -> (bool, Vec<String>) {
    let text = String::from_utf8_lossy(bytes);
    match mime.split(';').next() {
        Some("x-special/gnome-copied-files") => {
            let mut lines = text.lines();
            let cut = lines.next().is_some_and(|op| op.trim() == "cut");
            (cut, lines.map(str::to_owned).collect())
        }
        Some("text/uri-list") => (
            false,
            text.lines()
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_owned)
                .collect(),
        ),
        _ => (false, Vec::new()),
    }
}

/// Find an offered MIME whose base type (before `;`) is exactly `base`.
fn find_base<'a>(mimes: &'a [String], base: &str) -> Option<&'a str> {
    mimes
        .iter()
        .map(String::as_str)
        .find(|m| m.split(';').next() == Some(base))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn types(list: &[&str]) -> Vec<String> {
        list.iter().map(|t| (*t).to_owned()).collect()
    }

    #[test]
    fn chromium_style_rich_text() {
        // Real capture from this session: Chromium offering one copy.
        let mimes = types(&[
            "text/plain",
            "text/plain;charset=utf-8",
            "UTF8_STRING",
            "chromium/x-internal-source-rfh-token",
            "TEXT",
            "chromium/x-source-url",
            "STRING",
            "text/html",
        ]);
        assert_eq!(
            classify(&mimes),
            SelectionKind::RichText {
                html: "text/html".to_owned(),
                // find_mime_match prefers the exact charset variant over bare text/plain.
                plain: Some("text/plain;charset=utf-8".to_owned())
            }
        );
    }

    #[test]
    fn file_references_win_over_text() {
        let mimes = types(&[
            "x-special/gnome-copied-files",
            "text/uri-list",
            "text/plain",
        ]);
        assert_eq!(
            classify(&mimes),
            SelectionKind::Files {
                mimes: vec![
                    "x-special/gnome-copied-files".to_owned(),
                    "text/uri-list".to_owned()
                ]
            }
        );
    }

    #[test]
    fn images_prefer_png_then_fall_back_to_any_image() {
        assert_eq!(
            classify(&types(&["image/png"])),
            SelectionKind::Image {
                mime: "image/png".to_owned()
            }
        );
        assert_eq!(
            classify(&types(&["image/avif", "image/png"])),
            SelectionKind::Image {
                mime: "image/png".to_owned()
            }
        );
        assert_eq!(
            classify(&types(&["image/x-custom"])),
            SelectionKind::Image {
                mime: "image/x-custom".to_owned()
            }
        );
    }

    #[test]
    fn password_hint_beats_everything() {
        let mimes = types(&[
            "x-kde-passwordManagerHint",
            "text/plain;charset=utf-8",
            "text/html",
        ]);
        assert_eq!(classify(&mimes), SelectionKind::Sensitive);
    }

    #[test]
    fn plain_text_tolerates_charset_variants() {
        assert_eq!(
            classify(&types(&["text/plain"])),
            SelectionKind::PlainText {
                mime: "text/plain".to_owned()
            }
        );
        assert_eq!(
            classify(&types(&[
                "text/plain;charset=utf-8",
                "UTF8_STRING",
                "STRING",
                "TEXT"
            ])),
            SelectionKind::PlainText {
                mime: "text/plain;charset=utf-8".to_owned()
            }
        );
    }

    #[test]
    fn html_with_charset_parameter_is_still_rich_text() {
        assert_eq!(
            classify(&types(&[
                "text/html;charset=utf-8",
                "text/plain;charset=utf-8"
            ])),
            SelectionKind::RichText {
                html: "text/html;charset=utf-8".to_owned(),
                plain: Some("text/plain;charset=utf-8".to_owned())
            }
        );
    }

    #[test]
    fn unknown_types_pass_through_verbatim() {
        let mimes = types(&[
            "chromium/x-internal-source-rfh-token",
            "application/x-something",
        ]);
        assert_eq!(
            classify(&mimes),
            SelectionKind::Passthrough {
                mimes: mimes.clone()
            }
        );
        assert_eq!(classify(&[]), SelectionKind::Passthrough { mimes: vec![] });
    }

    #[test]
    fn gnome_file_refs_carry_the_cut_state() {
        let (_, uris) = parse_file_refs(
            "x-special/gnome-copied-files",
            b"copy\nfile:///home/a.pdf\nfile:///home/b.txt\n",
        );
        assert_eq!(uris, vec!["file:///home/a.pdf", "file:///home/b.txt"]);

        let (cut, uris) =
            parse_file_refs("x-special/gnome-copied-files", b"cut\nfile:///home/a.pdf\n");
        assert!(cut);
        assert_eq!(uris, vec!["file:///home/a.pdf"]);
    }

    #[test]
    fn uri_list_skips_comments_and_blank_lines() {
        let (_, uris) =
            parse_file_refs("text/uri-list", b"# comment\r\n\r\nfile:///home/a.pdf\r\n");
        assert_eq!(uris, vec!["file:///home/a.pdf"]);
    }
}
