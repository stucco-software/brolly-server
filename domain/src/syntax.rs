//! RDF serialization and parsing, and the media types we accept.
//!
//! Pure: bytes in, quads out, quads in, bytes out. No store, no network.
//!
//! **Reading and writing are deliberately asymmetric.** We serialize RDF/XML on
//! request but never parse it — `quick-xml 0.37.5` carries two unfixed
//! denial-of-service advisories reachable from federation input, the dependency
//! cannot be updated or removed, so the mitigation is to keep untrusted bytes
//! away from the parser (ADR 0007). Serialization is unaffected by either
//! advisory.

use oxrdf::Quad;
use oxrdfio::{JsonLdProfileSet, RdfFormat, RdfParser, RdfSerializer};

/// A syntax we will parse. RDF/XML is absent by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFormat {
    Turtle,
    NTriples,
    NQuads,
    TriG,
    JsonLd,
}

/// A syntax we will produce. Includes RDF/XML — output is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteFormat {
    Turtle,
    NTriples,
    NQuads,
    TriG,
    JsonLd,
    RdfXml,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyntaxError {
    /// The media type is not RDF we parse. Carries the type so the handler can
    /// name it in a `415`.
    Unsupported(String),
    /// Specifically RDF/XML, which we serialize but never parse. Distinguished
    /// from `Unsupported` so the response can explain rather than just refuse.
    RdfXmlNotAccepted,
    Parse(String),
    Serialize(String),
}

impl std::fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyntaxError::Unsupported(t) => write!(f, "unsupported media type: {t}"),
            SyntaxError::RdfXmlNotAccepted => write!(
                f,
                "application/rdf+xml is served but not accepted; \
                 send Turtle, N-Triples, N-Quads, TriG or JSON-LD"
            ),
            SyntaxError::Parse(e) => write!(f, "parse error: {e}"),
            SyntaxError::Serialize(e) => write!(f, "serialize error: {e}"),
        }
    }
}

impl std::error::Error for SyntaxError {}

impl ReadFormat {
    fn oxrdf(self) -> RdfFormat {
        match self {
            ReadFormat::Turtle => RdfFormat::Turtle,
            ReadFormat::NTriples => RdfFormat::NTriples,
            ReadFormat::NQuads => RdfFormat::NQuads,
            ReadFormat::TriG => RdfFormat::TriG,
            ReadFormat::JsonLd => RdfFormat::JsonLd {
                profile: JsonLdProfileSet::empty(),
            },
        }
    }
}

impl WriteFormat {
    fn oxrdf(self) -> RdfFormat {
        match self {
            WriteFormat::Turtle => RdfFormat::Turtle,
            WriteFormat::NTriples => RdfFormat::NTriples,
            WriteFormat::NQuads => RdfFormat::NQuads,
            WriteFormat::TriG => RdfFormat::TriG,
            WriteFormat::JsonLd => RdfFormat::JsonLd {
                profile: JsonLdProfileSet::empty(),
            },
            WriteFormat::RdfXml => RdfFormat::RdfXml,
        }
    }

    /// True for syntaxes that can express named graphs.
    ///
    /// Turtle, N-Triples and RDF/XML cannot, and oxrdfio refuses a quad
    /// carrying a graph name rather than silently dropping it. Every quad we
    /// store is in a named graph, so serializing to those formats has to strip
    /// it — which is the right answer for an LDP response already scoped to one
    /// resource's graph.
    pub fn supports_graphs(self) -> bool {
        matches!(
            self,
            WriteFormat::NQuads | WriteFormat::TriG | WriteFormat::JsonLd
        )
    }

    pub fn media_type(self) -> &'static str {
        match self {
            WriteFormat::Turtle => "text/turtle",
            WriteFormat::NTriples => "application/n-triples",
            WriteFormat::NQuads => "application/n-quads",
            WriteFormat::TriG => "application/trig",
            WriteFormat::JsonLd => "application/ld+json",
            WriteFormat::RdfXml => "application/rdf+xml",
        }
    }
}

/// Strip parameters: `text/turtle; charset=utf-8` → `text/turtle`.
/// The bare media type from a header value: `image/png; charset=x` → `image/png`.
///
/// Public because LDP-NR records the type it was given, and storing the
/// parameters would make `image/png` and `image/png; name=x` different types
/// for the same bytes.
pub fn media_type_of(header: &str) -> &str {
    header.split(';').next().unwrap_or(header).trim()
}

/// Resolve a request `Content-Type` to a parseable syntax.
pub fn read_format(content_type: &str) -> Result<ReadFormat, SyntaxError> {
    match media_type_of(content_type) {
        "text/turtle" | "application/x-turtle" => Ok(ReadFormat::Turtle),
        "application/n-triples" => Ok(ReadFormat::NTriples),
        "application/n-quads" => Ok(ReadFormat::NQuads),
        "application/trig" => Ok(ReadFormat::TriG),
        "application/ld+json" => Ok(ReadFormat::JsonLd),
        // Distinct error: we do serve this type, we just will not parse it.
        "application/rdf+xml" => Err(SyntaxError::RdfXmlNotAccepted),
        other => Err(SyntaxError::Unsupported(other.to_string())),
    }
}

/// True when a body of this type is RDF we will parse.
///
/// LDP write handlers use this to decide between the graph store and the binary
/// blob store. RDF/XML answers `false` here *and* errors in [`read_format`], so
/// it can never be silently stored as an opaque blob either.
pub fn is_parseable_rdf(content_type: &str) -> bool {
    read_format(content_type).is_ok()
}

fn quality(part: &str) -> f32 {
    part.split(';')
        .skip(1)
        .find_map(|p| p.trim().strip_prefix("q=")?.parse::<f32>().ok())
        .unwrap_or(1.0)
}

/// Choose a response syntax from an `Accept` header.
///
/// Turtle is the default: it is the Solid ecosystem's lingua franca and the
/// most readable when someone curls a resource by hand.
pub fn negotiate(accept: Option<&str>) -> WriteFormat {
    let Some(accept) = accept else {
        return WriteFormat::Turtle;
    };

    let mut best = (0.0_f32, None);
    for part in accept.split(',') {
        let q = quality(part);
        let format = match media_type_of(part) {
            "text/turtle" | "application/x-turtle" => Some(WriteFormat::Turtle),
            "application/n-triples" => Some(WriteFormat::NTriples),
            "application/n-quads" => Some(WriteFormat::NQuads),
            "application/trig" => Some(WriteFormat::TriG),
            "application/ld+json" => Some(WriteFormat::JsonLd),
            "application/rdf+xml" => Some(WriteFormat::RdfXml),
            "*/*" => Some(WriteFormat::Turtle),
            _ => None,
        };
        if let Some(format) = format
            && q > best.0
        {
            best = (q, Some(format));
        }
    }
    best.1.unwrap_or(WriteFormat::Turtle)
}

/// Parse a request body into quads.
pub fn parse(bytes: &[u8], format: ReadFormat, base: &str) -> Result<Vec<Quad>, SyntaxError> {
    let parser = RdfParser::from_format(format.oxrdf())
        .with_base_iri(base)
        .map_err(|e| SyntaxError::Parse(e.to_string()))?;

    parser
        .for_slice(bytes)
        .map(|quad| quad.map_err(|e| SyntaxError::Parse(e.to_string())))
        .collect()
}

/// Serialize quads for a response.
pub fn serialize(quads: &[Quad], format: WriteFormat) -> Result<Vec<u8>, SyntaxError> {
    let mut buffer = Vec::new();
    let mut serializer = RdfSerializer::from_format(format.oxrdf()).for_writer(&mut buffer);
    for quad in quads {
        let quad = if format.supports_graphs() {
            quad.clone()
        } else {
            // Move into the default graph. See `supports_graphs`.
            Quad::new(
                quad.subject.clone(),
                quad.predicate.clone(),
                quad.object.clone(),
                oxrdf::GraphName::DefaultGraph,
            )
        };
        serializer
            .serialize_quad(&quad)
            .map_err(|e| SyntaxError::Serialize(e.to_string()))?;
    }
    serializer
        .finish()
        .map_err(|e| SyntaxError::Serialize(e.to_string()))?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdf_xml_is_served_but_never_parsed() {
        // ADR 0007. Two unfixed DoS advisories in quick-xml are reachable from
        // federation input if we parse this.
        assert_eq!(
            read_format("application/rdf+xml"),
            Err(SyntaxError::RdfXmlNotAccepted)
        );
        assert!(!is_parseable_rdf("application/rdf+xml"));
        // Output is unaffected by both advisories.
        assert_eq!(negotiate(Some("application/rdf+xml")), WriteFormat::RdfXml);
    }

    #[test]
    fn rdf_xml_cannot_slip_through_as_a_binary_blob() {
        // If is_parseable_rdf said false and read_format said "unsupported",
        // an LDP PUT would helpfully store the XML as an opaque file. It must
        // be refused outright instead.
        assert!(matches!(
            read_format("application/rdf+xml"),
            Err(SyntaxError::RdfXmlNotAccepted)
        ));
    }

    #[test]
    fn parameters_do_not_defeat_type_matching() {
        assert_eq!(
            read_format("text/turtle; charset=utf-8"),
            Ok(ReadFormat::Turtle)
        );
        assert_eq!(
            read_format("application/rdf+xml; charset=utf-8"),
            Err(SyntaxError::RdfXmlNotAccepted)
        );
    }

    #[test]
    fn turtle_is_the_default_response_syntax() {
        assert_eq!(negotiate(None), WriteFormat::Turtle);
        assert_eq!(negotiate(Some("*/*")), WriteFormat::Turtle);
        assert_eq!(negotiate(Some("image/png")), WriteFormat::Turtle);
    }

    #[test]
    fn quality_values_are_respected() {
        assert_eq!(
            negotiate(Some("text/turtle;q=0.5, application/ld+json;q=0.9")),
            WriteFormat::JsonLd
        );
        assert_eq!(
            negotiate(Some("application/ld+json;q=0.2, text/turtle;q=0.8")),
            WriteFormat::Turtle
        );
    }

    #[test]
    fn named_graph_quads_serialize_to_triple_formats() {
        // Everything in the store carries a graph name, so this is the normal
        // case rather than an edge one.
        let quads = vec![Quad::new(
            oxrdf::NamedNode::new_unchecked("https://a.example/s"),
            oxrdf::NamedNode::new_unchecked("https://a.example/p"),
            oxrdf::NamedNode::new_unchecked("https://a.example/o"),
            oxrdf::NamedNode::new_unchecked("https://a.example/g"),
        )];

        for format in [
            WriteFormat::Turtle,
            WriteFormat::NTriples,
            WriteFormat::RdfXml,
        ] {
            let bytes = serialize(&quads, format).expect("graph name should be stripped");
            assert!(!bytes.is_empty(), "{format:?} produced nothing");
        }
        // Quad formats keep it.
        let nquads = String::from_utf8(serialize(&quads, WriteFormat::NQuads).unwrap()).unwrap();
        assert!(nquads.contains("https://a.example/g"));
    }

    #[test]
    fn turtle_round_trips_through_parse_and_serialize() {
        let turtle = br#"<https://alice.brolly.id/~/a> <https://example.org/p> "v" ."#;
        let quads = parse(turtle, ReadFormat::Turtle, "https://alice.brolly.id/~/").unwrap();
        assert_eq!(quads.len(), 1);

        let bytes = serialize(&quads, WriteFormat::NTriples).unwrap();
        let reparsed = parse(&bytes, ReadFormat::NTriples, "https://alice.brolly.id/~/").unwrap();
        assert_eq!(quads, reparsed);
    }

    #[test]
    fn relative_iris_resolve_against_the_base() {
        let turtle = br#"<> <https://example.org/p> "v" ."#;
        let quads = parse(turtle, ReadFormat::Turtle, "https://alice.brolly.id/~/note").unwrap();
        assert_eq!(
            quads[0].subject.to_string(),
            "<https://alice.brolly.id/~/note>"
        );
    }

    #[test]
    fn a_malformed_body_is_an_error_not_a_panic() {
        let result = parse(
            b"this is not turtle {{{",
            ReadFormat::Turtle,
            "https://a.example/",
        );
        assert!(matches!(result, Err(SyntaxError::Parse(_))));
    }

    #[test]
    fn unsupported_types_name_themselves() {
        assert_eq!(
            read_format("application/pdf"),
            Err(SyntaxError::Unsupported("application/pdf".into()))
        );
    }
}
