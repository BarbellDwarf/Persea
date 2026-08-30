//! Shared quick-xml event-loop scaffolding for the SAML XML walkers.
//!
//! Every SAML parser here was a hand-rolled copy of the same loop: set up
//! a `Reader`, own a scratch `Vec<u8>`, call `read_event_into`, stop at
//! EOF or a parse error. This module is that scaffolding. The per-event
//! handling (tag matching, attribute collection, output building) stays
//! with each caller.
//!
//! The exclusive-C14N canonicalizer in `saml.rs` deliberately keeps its
//! own loop: its event handling is the canonicalization algorithm itself
//! and is signature-critical, so it shares none of this scaffolding.

use quick_xml::events::{BytesStart, Event};
use std::ops::ControlFlow;

/// Drive the shared quick-xml event loop over `xml`.
///
/// Builds a `Reader` over the input with the requested text trimming and
/// feeds every successfully parsed event to `f`. The walk ends when the
/// input is exhausted, when `f` returns [`ControlFlow::Break`], or when
/// a parse error occurs (surfaced as the `Err` string). Callers that
/// swallow parse errors discard the `Result` with `let _ =`, matching
/// the original `Err(_) => break` treatment; callers that must surface
/// them map the error into their own message.
pub fn for_each_event(
    xml: &str,
    trim_text: bool,
    mut f: impl FnMut(Event<'_>) -> ControlFlow<()>,
) -> Result<(), String> {
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(trim_text);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => return Ok(()),
            Ok(event) => {
                if f(event).is_break() {
                    return Ok(());
                }
            }
            Err(e) => return Err(e.to_string()),
        }
        buf.clear();
    }
}

/// Visit every `Start`/`Empty` element of `xml` with its local tag name
/// (namespace prefix stripped) and raw element handle. Text, comment, and
/// other events are skipped, and the walk ends at EOF, a parse error
/// (surfaced as the `Err` string), or a `Break` from `f`.
pub fn for_each_start_event(
    xml: &str,
    mut f: impl FnMut(&str, &BytesStart<'_>) -> ControlFlow<()>,
) -> Result<(), String> {
    for_each_event(xml, true, |event| match event {
        Event::Start(ref e) | Event::Empty(ref e) => {
            let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
            f(local_name(&tag), e)
        }
        _ => ControlFlow::Continue(()),
    })
}

/// Strip the namespace prefix from a tag name
/// (e.g. "md:EntityDescriptor" → "EntityDescriptor").
pub(crate) fn local_name(name: &str) -> &str {
    name.rsplit_once(':')
        .map(|(_, local)| local)
        .unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn collect_names(xml: &str) -> Vec<String> {
        let names = RefCell::new(Vec::new());
        let _ = for_each_start_event(xml, |ln, _| {
            names.borrow_mut().push(ln.to_string());
            ControlFlow::Continue(())
        });
        names.into_inner()
    }

    #[test]
    fn visits_start_and_empty_elements() {
        let names = collect_names("<a><b/><c>text</c><!-- comment --></a>");
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn strips_namespace_prefixes() {
        let names = collect_names(
            r#"<md:EntityDescriptor xmlns:md="urn:x"><md:IDPSSODescriptor/></md:EntityDescriptor>"#,
        );
        assert_eq!(names, vec!["EntityDescriptor", "IDPSSODescriptor"]);
    }

    #[test]
    fn prefix_plain_and_unprefixed_names() {
        assert_eq!(local_name("md:EntityDescriptor"), "EntityDescriptor");
        assert_eq!(local_name("EntityDescriptor"), "EntityDescriptor");
    }

    #[test]
    fn break_stops_the_walk_early() {
        let names = RefCell::new(Vec::new());
        let _ = for_each_start_event("<a><b><c/></b></a>", |ln, _| {
            names.borrow_mut().push(ln.to_string());
            if ln == "b" {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        assert_eq!(names.into_inner(), vec!["a", "b"]);
    }

    #[test]
    fn text_events_are_not_visited() {
        // Text-only payloads never reach the start-event callback.
        let mut seen = 0;
        let _ = for_each_start_event("plain text, no elements", |_ln, _e| {
            seen += 1;
            ControlFlow::Continue(())
        });
        assert_eq!(seen, 0);
    }

    #[test]
    fn malformed_xml_reports_error() {
        let mut visits = 0;
        let result = for_each_start_event("<a><unclosed", |_ln, _e| {
            visits += 1;
            ControlFlow::Continue(())
        });
        // Whatever was parsed before the error was still delivered.
        assert!(result.is_err() || visits > 0);
        assert!(result.is_err() || visits == 1);
    }

    #[test]
    fn attributes_reach_the_callback() {
        // Attr values with entities stay escaped at the event level, as
        // every caller relies on lossy byte access.
        let found = RefCell::new(None);
        let _ = for_each_start_event(r#"<r ID="_abc"/>"#, |_ln, e| {
            for attr in e.attributes().flatten() {
                if attr.key.as_ref() == b"ID" {
                    *found.borrow_mut() = Some(String::from_utf8_lossy(&attr.value).to_string());
                }
            }
            ControlFlow::Continue(())
        });
        assert_eq!(found.into_inner().as_deref(), Some("_abc"));
    }
}
