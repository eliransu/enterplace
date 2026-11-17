//! Console sign-in through a SAML 2.0 identity provider: Enterplace is the service provider, with the Web Browser SSO
//! profile (SAML 2.0 Profiles, section 4.1): the request goes out with the HTTP-Redirect binding, the response
//! comes back with HTTP-POST.
//!
//! The assertion Enterplace reads must be covered by an XML signature (XML Signature 1.1) that verifies against the
//! certificate in the policy: on the assertion itself, or on the response that holds it. Only enveloped signatures
//! with exclusive canonicalization (Exclusive XML Canonicalization 1.0, without comments) and SHA-256 or SHA-512
//! are taken. Every value is read from the very element the signature covers, found by the ID its reference
//! names, which must be on exactly one element: so a signed element moved elsewhere, or a second unsigned
//! assertion beside it, is never what Enterplace reads ("signature wrapping"). Encrypted assertions are refused.
//!
//! Every check fails closed with a code for the audit record and a message that names the cause and the fix.

use std::collections::BTreeMap;

use enterplace_core::{config::Saml, x509};
use ring::signature::{self, UnparsedPublicKey};
use roxmltree::{Document, Node, NodeId, NodeType};

use crate::sso::Refusal;

const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const EMAIL_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
/// Clock difference allowed between Enterplace and the identity provider.
const LEEWAY: i64 = 60;
/// No real response is near this size; a larger one is refused before it is parsed.
pub(crate) const MAX_RESPONSE: usize = 512 * 1024;

fn refuse(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        code,
        message: message.into(),
    }
}

/// What a verified assertion says about the person.
#[derive(Debug)]
pub(crate) struct Signed {
    /// Lower case.
    pub email: String,
    /// Values of the role attribute.
    pub groups: Vec<String>,
    /// The assertion's ID, used once.
    pub id: String,
    /// Unix seconds after which the assertion is no longer good, so its ID need not be remembered past it.
    pub until: i64,
}

/// The address the browser is sent to with a request to sign in: the identity provider's SSO URL with a deflated
/// `AuthnRequest` and `RelayState` (SAML 2.0 Bindings, section 3.4).
pub(crate) fn authn_url(saml: &Saml, id: &str, now: i64, relay: &str) -> String {
    let request = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{id}" Version="2.0" IssueInstant="{}" Destination="{}" AssertionConsumerServiceURL="{}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>{}</saml:Issuer><samlp:NameIDPolicy AllowCreate="true"/></samlp:AuthnRequest>"#,
        instant(now),
        attr(&saml.idp_sso_url),
        attr(&saml.acs_url),
        text(&saml.sp_entity_id),
    );
    let join = if saml.idp_sso_url.contains('?') {
        '&'
    } else {
        '?'
    };
    format!(
        "{}{join}SAMLRequest={}&RelayState={}",
        saml.idp_sso_url,
        crate::html::enc(&x509::base64_encode(&stored_deflate(request.as_bytes()))),
        crate::html::enc(relay)
    )
}

/// DEFLATE (RFC 1951) in stored blocks: valid input to every inflater, and no compressor to carry for a request
/// of a few hundred bytes.
fn stored_deflate(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / 65_535 + 1));
    let chunks: Vec<&[u8]> = if data.is_empty() {
        vec![data]
    } else {
        data.chunks(65_535).collect()
    };
    for (i, chunk) in chunks.iter().enumerate() {
        out.push(u8::from(i + 1 == chunks.len()));
        let len = u16::try_from(chunk.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

/// The service provider's metadata (SAML 2.0 Metadata), for identity providers that read it.
pub(crate) fn metadata(saml: &Saml) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="{PROTOCOL}">
    <md:NameIDFormat>{EMAIL_FORMAT}</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{}" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"#,
        attr(&saml.sp_entity_id),
        attr(&saml.acs_url)
    )
}

fn text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn attr(s: &str) -> String {
    text(s).replace('"', "&quot;")
}

/// `xs:dateTime` in UTC, as SAML writes instants.
fn instant(unix: i64) -> String {
    jiff::Timestamp::from_second(unix)
        .map(|t| t.strftime("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

fn unix(text: &str) -> Option<i64> {
    text.trim()
        .parse::<jiff::Timestamp>()
        .ok()
        .map(|t| t.as_second())
}

fn is(node: &Node<'_, '_>, ns: &str, name: &str) -> bool {
    node.is_element() && node.tag_name().namespace() == Some(ns) && node.tag_name().name() == name
}

fn child<'a, 'i>(node: Node<'a, 'i>, ns: &str, name: &str) -> Option<Node<'a, 'i>> {
    node.children().find(|c| is(c, ns, name))
}

fn children<'a, 'i>(
    node: Node<'a, 'i>,
    ns: &'a str,
    name: &'a str,
) -> impl Iterator<Item = Node<'a, 'i>> + 'a {
    node.children().filter(move |c| is(c, ns, name))
}

fn content(node: Option<Node<'_, '_>>) -> String {
    node.map(|n| {
        n.descendants()
            .filter(|d| d.node_type() == NodeType::Text)
            .filter_map(|d| d.text())
            .collect::<String>()
            .trim()
            .to_string()
    })
    .unwrap_or_default()
}

/// Checks a `SAMLResponse` (base64, as posted) against the policy's `console.saml`, for the request `request_id`,
/// at `now` (Unix seconds), and returns who it says signed in.
pub(crate) fn verify(
    posted: &str,
    saml: &Saml,
    request_id: &str,
    now: i64,
) -> Result<Signed, Refusal> {
    let bad = |what: &str| {
        refuse(
            "saml_response",
            format!(
                "The identity provider's response could not be read: {what}. Start again from the sign-in page; if it repeats, check the SAML app at the identity provider."
            ),
        )
    };
    let bytes = x509::base64_decode(posted).ok_or_else(|| bad("SAMLResponse is not base64"))?;
    let xml = String::from_utf8(bytes).map_err(|_| bad("it is not UTF-8"))?;
    // A DOCTYPE is refused by the parser (no entity expansion, no external entities).
    let doc = Document::parse(&xml)
        .map_err(|err| bad(&format!("it is not XML Enterplace takes ({err})")))?;
    let response = doc.root_element();
    if !is(&response, PROTOCOL, "Response") {
        return Err(bad("its root is not a samlp:Response"));
    }
    if response.attribute("Version") != Some("2.0") {
        return Err(bad("it is not SAML 2.0"));
    }
    let status = child(response, PROTOCOL, "Status")
        .and_then(|s| child(s, PROTOCOL, "StatusCode"))
        .and_then(|c| c.attribute("Value"))
        .unwrap_or("");
    if status != SUCCESS {
        return Err(refuse(
            "saml_status",
            format!(
                "The identity provider did not sign you in (status {status}). Check that you are assigned to the Enterplace app at the identity provider, then start again."
            ),
        ));
    }
    if let Some(destination) = response.attribute("Destination")
        && destination != saml.acs_url
    {
        return Err(refuse(
            "saml_recipient",
            format!(
                "The response was sent to {destination}, not to this console's {}. Set the ACS (reply) URL of the SAML app to console.saml.acs_url.",
                saml.acs_url
            ),
        ));
    }
    if response.attribute("InResponseTo") != Some(request_id) {
        return Err(refuse(
            "saml_replay",
            "The response does not answer the sign-in this browser started, so it may be replayed or started at the identity provider. Start again from the console's sign-in page.",
        ));
    }
    if response
        .descendants()
        .any(|n| is(&n, ASSERTION, "EncryptedAssertion"))
    {
        return Err(refuse(
            "saml_encrypted",
            "The assertion is encrypted, which Enterplace does not take. Turn off assertion encryption in the SAML app; the assertion travels over TLS and is signed.",
        ));
    }
    let assertions: Vec<Node<'_, '_>> = children(response, ASSERTION, "Assertion").collect();
    let [assertion] = assertions[..] else {
        return Err(bad(&format!(
            "it holds {} assertions directly in the response, not exactly one",
            assertions.len()
        )));
    };
    if response
        .descendants()
        .filter(|n| is(n, ASSERTION, "Assertion"))
        .count()
        != 1
    {
        return Err(bad("it holds an assertion nested somewhere else"));
    }
    // The assertion must be covered by a signature that verifies: its own, or the response's. Each signature that
    // is there must verify.
    let mut covered = false;
    for (element, label) in [(assertion, "assertion"), (response, "response")] {
        let signatures: Vec<Node<'_, '_>> = children(element, DSIG, "Signature").collect();
        match signatures[..] {
            [] => {}
            [one] => {
                verify_signature(&doc, element, one, &saml.idp_certificates, label)?;
                covered = true;
            }
            _ => return Err(bad(&format!("its {label} has more than one signature"))),
        }
    }
    if !covered {
        return Err(refuse(
            "saml_unsigned",
            "The assertion is not signed, so it was refused. Turn on assertion signing (or response signing) in the SAML app at the identity provider.",
        ));
    }
    if assertion.attribute("Version") != Some("2.0") {
        return Err(bad("the assertion is not SAML 2.0"));
    }
    let issuer = content(child(assertion, ASSERTION, "Issuer"));
    let response_issuer = child(response, ASSERTION, "Issuer").map(|i| content(Some(i)));
    if issuer != saml.idp_entity_id
        || response_issuer
            .as_ref()
            .is_some_and(|r| *r != saml.idp_entity_id)
    {
        return Err(refuse(
            "saml_issuer",
            format!(
                "The assertion was issued by \"{issuer}\", not \"{}\". Copy the identity provider's entity ID exactly into console.saml.idp_entity_id.",
                saml.idp_entity_id
            ),
        ));
    }
    let id = assertion.attribute("ID").unwrap_or("").to_string();
    // Conditions: the time window and the audience.
    let conditions = child(assertion, ASSERTION, "Conditions").ok_or_else(|| {
        refuse(
            "saml_audience",
            "The assertion has no Conditions, so no audience. Set the audience (SP entity ID) of the SAML app to console.saml.sp_entity_id.",
        )
    })?;
    let expired = refuse(
        "saml_expired",
        "The assertion has expired or is not valid yet. Start again from the sign-in page; if it repeats, check that this machine's clock and the identity provider's agree.",
    );
    if let Some(before) = conditions.attribute("NotBefore") {
        if unix(before).is_none_or(|t| t > now + LEEWAY) {
            return Err(expired);
        }
    }
    let mut until = match conditions.attribute("NotOnOrAfter") {
        Some(after) => unix(after).ok_or_else(|| bad("NotOnOrAfter is not a time"))?,
        None => i64::MAX,
    };
    if until + LEEWAY <= now {
        return Err(expired);
    }
    let restrictions: Vec<Node<'_, '_>> =
        children(conditions, ASSERTION, "AudienceRestriction").collect();
    let audience_ok = !restrictions.is_empty()
        && restrictions.iter().all(|r| {
            children(*r, ASSERTION, "Audience").any(|a| content(Some(a)) == saml.sp_entity_id)
        });
    if !audience_ok {
        return Err(refuse(
            "saml_audience",
            format!(
                "The assertion was issued for another service provider, not \"{}\". Set the audience (SP entity ID) of the SAML app to console.saml.sp_entity_id.",
                saml.sp_entity_id
            ),
        ));
    }
    // The subject: a bearer confirmation for this console's ACS, this request, still in time.
    let subject = child(assertion, ASSERTION, "Subject")
        .ok_or_else(|| bad("the assertion has no Subject"))?;
    let mut confirmed = None;
    for confirmation in children(subject, ASSERTION, "SubjectConfirmation") {
        if confirmation.attribute("Method") != Some(BEARER) {
            continue;
        }
        let Some(data) = child(confirmation, ASSERTION, "SubjectConfirmationData") else {
            continue;
        };
        let deadline = data.attribute("NotOnOrAfter").and_then(unix);
        let fits = data.attribute("Recipient") == Some(saml.acs_url.as_str())
            && data
                .attribute("InResponseTo")
                .is_none_or(|r| r == request_id)
            && deadline.is_some_and(|t| t + LEEWAY > now)
            && data
                .attribute("NotBefore")
                .is_none_or(|b| unix(b).is_some_and(|t| t <= now + LEEWAY));
        if fits {
            confirmed = deadline;
            break;
        }
    }
    let Some(deadline) = confirmed else {
        return Err(refuse(
            "saml_recipient",
            format!(
                "The assertion has no bearer confirmation for {} that is still in time. Set the ACS (reply) URL of the SAML app to console.saml.acs_url, and start again.",
                saml.acs_url
            ),
        ));
    };
    until = until.min(deadline);
    // Attributes, by Name or FriendlyName.
    let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for statement in children(assertion, ASSERTION, "AttributeStatement") {
        for attribute in children(statement, ASSERTION, "Attribute") {
            let values: Vec<String> = children(attribute, ASSERTION, "AttributeValue")
                .map(|v| content(Some(v)))
                .filter(|v| !v.is_empty())
                .collect();
            for name in [
                attribute.attribute("Name"),
                attribute.attribute("FriendlyName"),
            ]
            .into_iter()
            .flatten()
            {
                attributes
                    .entry(name.to_string())
                    .or_default()
                    .extend(values.iter().cloned());
            }
        }
    }
    let name_id = child(subject, ASSERTION, "NameID");
    let email = match &saml.email_attribute {
        Some(name) => attributes
            .get(name)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default(),
        None => {
            let format = name_id.and_then(|n| n.attribute("Format")).unwrap_or("");
            let value = content(name_id);
            if format == EMAIL_FORMAT || (format.ends_with(":unspecified") || format.is_empty()) {
                value
            } else {
                String::new()
            }
        }
    }
    .trim()
    .to_ascii_lowercase();
    if !email.contains('@') {
        return Err(refuse(
            "sso_email",
            match &saml.email_attribute {
                Some(name) => format!(
                    "The assertion has no email in attribute \"{name}\". Add an attribute statement with that name holding the email to the SAML app, or fix console.saml.email_attribute."
                ),
                None => "The assertion's NameID is not an email. Set the SAML app's NameID format to emailAddress, or set console.saml.email_attribute to the attribute that holds the email.".to_string(),
            },
        ));
    }
    let groups = attributes
        .get(&saml.role_attribute)
        .cloned()
        .unwrap_or_default();
    Ok(Signed {
        email,
        groups,
        id,
        until,
    })
}

/// Verifies the enveloped `signature` of `element` (the assertion or the response) against the certificates.
fn verify_signature(
    doc: &Document<'_>,
    element: Node<'_, '_>,
    signature: Node<'_, '_>,
    certificates: &[Vec<u8>],
    label: &str,
) -> Result<(), Refusal> {
    let bad = |what: String| {
        refuse(
            "saml_signature",
            format!(
                "The {label}'s signature was refused: {what}. Check the SAML app's signing settings (RSA-SHA256 and exclusive canonicalization are what Enterplace takes), then start again."
            ),
        )
    };
    let info =
        child(signature, DSIG, "SignedInfo").ok_or_else(|| bad("it has no SignedInfo".into()))?;
    let method = |name: &str| {
        child(info, DSIG, name)
            .and_then(|n| n.attribute("Algorithm"))
            .unwrap_or("")
            .to_string()
    };
    if method("CanonicalizationMethod") != EXC_C14N {
        return Err(bad(format!(
            "SignedInfo is canonicalized with \"{}\", and Enterplace takes exclusive canonicalization only",
            method("CanonicalizationMethod")
        )));
    }
    let references: Vec<Node<'_, '_>> = children(info, DSIG, "Reference").collect();
    let [reference] = references[..] else {
        return Err(bad(format!(
            "it has {} references, not exactly one",
            references.len()
        )));
    };
    let id = element.attribute("ID").unwrap_or("");
    if id.is_empty() || reference.attribute("URI") != Some(&format!("#{id}")) {
        return Err(bad(format!(
            "it signs \"{}\", not this {label} (#{id})",
            reference.attribute("URI").unwrap_or("")
        )));
    }
    // The ID must name one element only, or the reference could be read as naming another.
    let named = doc
        .descendants()
        .filter(|n| {
            n.is_element()
                && n.attributes()
                    .any(|a| a.name().eq_ignore_ascii_case("id") && a.value() == id)
        })
        .count();
    if named != 1 {
        return Err(bad(format!("the ID {id} is on {named} elements")));
    }
    let mut prefixes = Vec::new();
    let transforms: Vec<Node<'_, '_>> = child(reference, DSIG, "Transforms")
        .map(|t| children(t, DSIG, "Transform").collect())
        .unwrap_or_default();
    let algorithms: Vec<&str> = transforms
        .iter()
        .map(|t| t.attribute("Algorithm").unwrap_or(""))
        .collect();
    let fits = matches!(algorithms[..], [ENVELOPED, EXC_C14N] | [EXC_C14N]);
    if !fits {
        return Err(bad(format!(
            "its transforms are [{}], and Enterplace takes the enveloped signature with exclusive canonicalization",
            algorithms.join(", ")
        )));
    }
    if let Some(list) = transforms
        .last()
        .and_then(|t| child(*t, EXC_C14N, "InclusiveNamespaces"))
        .and_then(|n| n.attribute("PrefixList"))
    {
        prefixes = list.split_whitespace().map(str::to_string).collect();
    }
    let digest_method = child(reference, DSIG, "DigestMethod")
        .and_then(|n| n.attribute("Algorithm"))
        .unwrap_or("");
    let digest_alg = match digest_method {
        "http://www.w3.org/2001/04/xmlenc#sha256" => &ring::digest::SHA256,
        "http://www.w3.org/2001/04/xmlenc#sha512" => &ring::digest::SHA512,
        other => {
            return Err(bad(format!(
                "the digest is \"{other}\", and Enterplace takes SHA-256 or SHA-512 (SHA-1 is broken)"
            )));
        }
    };
    let canonical = canonicalize(element, Some(signature.id()), &prefixes);
    let digest = ring::digest::digest(digest_alg, canonical.as_bytes());
    let given = x509::base64_decode(&content(child(reference, DSIG, "DigestValue")))
        .ok_or_else(|| bad("its DigestValue is not base64".into()))?;
    if digest.as_ref() != given.as_slice() {
        return Err(bad(format!(
            "the {label} was changed after it was signed (its digest does not match)"
        )));
    }
    let info_prefixes: Vec<String> = child(info, DSIG, "CanonicalizationMethod")
        .and_then(|c| child(c, EXC_C14N, "InclusiveNamespaces"))
        .and_then(|n| n.attribute("PrefixList"))
        .map(|l| l.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    let signed = canonicalize(info, None, &info_prefixes);
    let value = x509::base64_decode(&content(child(signature, DSIG, "SignatureValue")))
        .ok_or_else(|| bad("its SignatureValue is not base64".into()))?;
    let (algorithm, ec): (&'static dyn signature::VerificationAlgorithm, bool) = match method(
        "SignatureMethod",
    )
    .as_str()
    {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => {
            (&signature::RSA_PKCS1_2048_8192_SHA256, false)
        }
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => {
            (&signature::RSA_PKCS1_2048_8192_SHA512, false)
        }
        // XML Signature writes ECDSA as r then s, fixed width (RFC 4051 section 3.3).
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => {
            (&signature::ECDSA_P256_SHA256_FIXED, true)
        }
        other => {
            return Err(bad(format!(
                "it is signed with \"{other}\", and Enterplace takes RSA-SHA256, RSA-SHA512 or ECDSA-SHA256"
            )));
        }
    };
    let ok = certificates.iter().any(|der| {
        let key = match x509::public_key(der) {
            Ok(x509::PublicKey::Rsa(k)) if !ec => k,
            Ok(x509::PublicKey::EcP256(k)) if ec => k,
            _ => return false,
        };
        UnparsedPublicKey::new(algorithm, key)
            .verify(signed.as_bytes(), &value)
            .is_ok()
    });
    if !ok {
        return Err(refuse(
            "saml_signature",
            format!(
                "The {label}'s signature does not verify with the certificate in console.saml.idp_certificate. If the identity provider rotated its certificate, paste the new one there (both can be listed during the change); otherwise the response did not come from it."
            ),
        ));
    }
    Ok(())
}

/// The qualified name of an element as written, from the source text: canonical form keeps the prefix.
fn qname<'i>(node: Node<'_, 'i>, input: &'i str) -> &'i str {
    let start = node.range().start + 1;
    let rest = input.get(start..).unwrap_or("");
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
        .unwrap_or(rest.len());
    &rest[..end]
}

fn prefix_of(qname: &str) -> &str {
    qname.split_once(':').map_or("", |(p, _)| p)
}

/// Exclusive XML Canonicalization 1.0 without comments of the subtree at `apex`, leaving out `skip` (the enveloped
/// signature). `inclusive` is the InclusiveNamespaces PrefixList, `#default` for the default namespace.
fn canonicalize(apex: Node<'_, '_>, skip: Option<NodeId>, inclusive: &[String]) -> String {
    let mut out = String::new();
    let input = apex.document().input_text();
    element(apex, skip, inclusive, input, &BTreeMap::new(), &mut out);
    out
}

fn element(
    node: Node<'_, '_>,
    skip: Option<NodeId>,
    inclusive: &[String],
    input: &str,
    rendered: &BTreeMap<String, String>,
    out: &mut String,
) {
    let name = qname(node, input);
    let in_scope: BTreeMap<&str, &str> = node
        .namespaces()
        .map(|ns| (ns.name().unwrap_or(""), ns.uri()))
        .filter(|(p, _)| *p != "xml")
        .collect();
    let attrs: Vec<(&str, &str, &str, &str)> = node
        .attributes()
        .map(|a| {
            let q = input.get(a.range_qname()).unwrap_or(a.name());
            (a.namespace().unwrap_or(""), a.name(), q, a.value())
        })
        .collect();
    // Namespaces the element visibly uses, and those the PrefixList names that are in scope.
    let mut used: Vec<&str> = vec![prefix_of(name)];
    for (_, _, q, _) in &attrs {
        let p = prefix_of(q);
        if !p.is_empty() && p != "xml" {
            used.push(p);
        }
    }
    for p in inclusive {
        let p = if p == "#default" { "" } else { p.as_str() };
        if p.is_empty() || in_scope.contains_key(p) {
            used.push(p);
        }
    }
    used.sort_unstable();
    used.dedup();
    let mut now = rendered.clone();
    let mut decls = String::new();
    for p in used {
        let uri = in_scope.get(p).copied().unwrap_or("");
        let before = rendered.get(p).map_or("", String::as_str);
        if before == uri && (rendered.contains_key(p) || uri.is_empty()) {
            continue;
        }
        if p.is_empty() {
            decls.push_str(&format!(" xmlns=\"{}\"", escape_attr(uri)));
        } else {
            decls.push_str(&format!(" xmlns:{p}=\"{}\"", escape_attr(uri)));
        }
        now.insert(p.to_string(), uri.to_string());
    }
    let mut sorted = attrs;
    sorted.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    out.push('<');
    out.push_str(name);
    out.push_str(&decls);
    for (_, _, q, v) in &sorted {
        out.push_str(&format!(" {q}=\"{}\"", escape_attr(v)));
    }
    out.push('>');
    for c in node.children() {
        if Some(c.id()) == skip {
            continue;
        }
        match c.node_type() {
            NodeType::Element => element(c, skip, inclusive, input, &now, out),
            NodeType::Text => out.push_str(&escape_text(c.text().unwrap_or(""))),
            NodeType::PI => {
                if let Some(pi) = c.pi() {
                    out.push_str("<?");
                    out.push_str(pi.target);
                    if let Some(v) = pi.value.filter(|v| !v.is_empty()) {
                        out.push(' ');
                        out.push_str(v);
                    }
                    out.push_str("?>");
                }
            }
            _ => {}
        }
    }
    out.push_str("</");
    out.push_str(name);
    out.push('>');
}

fn escape_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\r', "&#xD;")
}

fn escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
        .replace('\r', "&#xD;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c14n(xml: &str, path: &[&str], inclusive: &[&str]) -> Result<String, String> {
        let doc = Document::parse(xml).map_err(|e| e.to_string())?;
        let mut node = doc.root_element();
        for name in path {
            node = node
                .children()
                .find(|c| c.is_element() && c.tag_name().name() == *name)
                .ok_or("no such element")?;
        }
        let inclusive: Vec<String> = inclusive.iter().map(|s| s.to_string()).collect();
        Ok(canonicalize(node, None, &inclusive))
    }

    #[test]
    fn exclusive_canonical_form_follows_the_specification() -> Result<(), String> {
        // Exclusive C14N 1.0, section 2.2: only visibly used namespaces are rendered, at the apex.
        let xml = r#"<n0:local xmlns:n0="foo:bar" xmlns:n3="ftp://example.org"><n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org"/></n1:elem2></n0:local>"#;
        assert_eq!(
            c14n(xml, &["elem2"], &[])?,
            r#"<n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org"></n3:stuff></n1:elem2>"#
        );
        // An InclusiveNamespaces prefix in scope is rendered even when unused.
        assert_eq!(
            c14n(xml, &["elem2"], &["n0"])?,
            r#"<n1:elem2 xmlns:n0="foo:bar" xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org"></n3:stuff></n1:elem2>"#
        );
        // Attributes sorted by namespace then name, values and text escaped, empty elements expanded, a
        // declaration rendered by an ancestor not rendered again, and xmlns="" only where it changes something.
        let xml = "<a xmlns=\"urn:d\" xmlns:p=\"urn:p\" z=\"1\" p:b=\"x&#9;y\" b=\"&quot;&lt;\"><p:c p:d=\"1\">t &amp; &lt;&gt;\r\nu</p:c><e xmlns=\"\"/></a>";
        assert_eq!(
            c14n(xml, &[], &[])?,
            "<a xmlns=\"urn:d\" xmlns:p=\"urn:p\" b=\"&quot;&lt;\" z=\"1\" p:b=\"x&#x9;y\"><p:c p:d=\"1\">t &amp; &lt;&gt;\nu</p:c><e xmlns=\"\"></e></a>"
        );
        Ok(())
    }

    #[test]
    fn stored_deflate_frames_blocks() {
        let out = stored_deflate(b"abc");
        assert_eq!(out, [1, 3, 0, 0xfc, 0xff, b'a', b'b', b'c']);
        let big = vec![7u8; 70_000];
        let out = stored_deflate(&big);
        assert_eq!(out[0], 0);
        assert_eq!(out[5 + 65_535], 1);
        assert_eq!(out.len(), 70_000 + 10);
    }

    #[test]
    fn a_doctype_is_refused_before_anything_is_read() {
        let xml = r#"<!DOCTYPE r [<!ENTITY e "x">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&e;</samlp:Response>"#;
        let saml = Saml {
            idp_entity_id: "idp".into(),
            idp_sso_url: "https://idp".into(),
            idp_certificates: Vec::new(),
            sp_entity_id: "sp".into(),
            acs_url: "https://sp/console/saml/acs".into(),
            email_attribute: None,
            role_attribute: "groups".into(),
            admin_values: Vec::new(),
            read_only_values: Vec::new(),
            allowed_domains: Vec::new(),
            allowed_emails: Vec::new(),
            self_issue: None,
        };
        let refused = verify(&x509::base64_encode(xml.as_bytes()), &saml, "_r", 0);
        assert!(refused.is_err_and(|r| r.code == "saml_response"));
    }

    /// A response signed by libxml2's exclusive canonicalization (the one xmlsec uses) and OpenSSL, in the shape
    /// identity providers send: pretty printed, namespaces on the root, attributes out of order, an
    /// InclusiveNamespaces prefix list, and the signature inside the assertion.
    const SIGNED: &str = include_str!("../tests/fixtures/saml-response.xml");
    const CERT: &str = include_str!("../tests/fixtures/saml-idp.pem");
    const NOW: i64 = 1_800_000_000;

    fn policy() -> Saml {
        Saml {
            idp_entity_id: "http://idp.example.com/metadata".into(),
            idp_sso_url: "https://idp.example.com/sso".into(),
            idp_certificates: enterplace_core::config::pem_certificates(CERT),
            sp_entity_id: "https://enterplace.example.com/console/saml/metadata".into(),
            acs_url: "https://enterplace.example.com/console/saml/acs".into(),
            email_attribute: None,
            role_attribute: "groups".into(),
            admin_values: vec!["enterplace-admins & friends".into()],
            read_only_values: Vec::new(),
            allowed_domains: vec!["example.com".into()],
            allowed_emails: Vec::new(),
            self_issue: None,
        }
    }

    fn check(xml: &str, saml: &Saml, request: &str, now: i64) -> Result<Signed, &'static str> {
        verify(&x509::base64_encode(xml.as_bytes()), saml, request, now).map_err(|r| r.code)
    }

    #[test]
    fn a_response_signed_by_another_implementation_verifies() -> Result<(), String> {
        let signed = check(SIGNED, &policy(), "_req1", NOW).map_err(str::to_string)?;
        assert_eq!(signed.email, "dana@example.com");
        assert_eq!(signed.groups, ["staff", "enterplace-admins & friends"]);
        assert_eq!(signed.id, "_assert1");
        let mut by_attribute = policy();
        by_attribute.email_attribute = Some("email".into());
        let signed = check(SIGNED, &by_attribute, "_req1", NOW).map_err(str::to_string)?;
        assert_eq!(signed.email, "dana@example.com");
        Ok(())
    }

    #[test]
    fn a_changed_unsigned_wrapped_or_misdirected_response_is_refused() {
        let saml = policy();
        // One character of a signed value changed.
        let changed = SIGNED.replace(">staff<", ">staff2<");
        assert_eq!(
            check(&changed, &saml, "_req1", NOW).err(),
            Some("saml_signature")
        );
        // The signature taken out.
        let start = SIGNED.find("<ds:Signature").unwrap_or(0);
        let end = SIGNED
            .find("</ds:Signature>")
            .map_or(0, |e| e + "</ds:Signature>".len());
        let unsigned = format!("{}{}", &SIGNED[..start], &SIGNED[end..]);
        assert_eq!(
            check(&unsigned, &saml, "_req1", NOW).err(),
            Some("saml_unsigned")
        );
        // A second, unsigned assertion beside the signed one, or the signed one wrapped elsewhere.
        let assertion_at = SIGNED.find("<saml:Assertion").unwrap_or(0);
        let evil = "<saml:Assertion Version=\"2.0\" ID=\"_evil\"><saml:Issuer>http://idp.example.com/metadata</saml:Issuer></saml:Assertion>";
        let two = format!(
            "{}{evil}{}",
            &SIGNED[..assertion_at],
            &SIGNED[assertion_at..]
        );
        assert_eq!(
            check(&two, &saml, "_req1", NOW).err(),
            Some("saml_response")
        );
        // The signed assertion moved into Extensions and a forged one with its ID put where it was.
        let assertion_end = SIGNED
            .find("</saml:Assertion>")
            .map_or(0, |e| e + "</saml:Assertion>".len());
        let forged =
            SIGNED[assertion_at..assertion_end].replace("Dana@Example.com", "eve@example.com");
        let forged = forged
            .get(..forged.find("<ds:Signature").unwrap_or(0))
            .unwrap_or("")
            .to_string()
            + &forged[forged.find("</ds:Signature>").map_or(0, |e| e + 15)..];
        let wrapped = format!(
            "{}<samlp:Extensions>{}</samlp:Extensions>{forged}{}",
            &SIGNED[..assertion_at],
            &SIGNED[assertion_at..assertion_end],
            &SIGNED[assertion_end..]
        );
        assert!(check(&wrapped, &saml, "_req1", NOW).is_err());
        // Another certificate.
        let mut other = saml.clone();
        other.idp_certificates = enterplace_core::config::pem_certificates(include_str!(
            "../tests/fixtures/saml-other-idp.pem"
        ));
        assert_eq!(
            check(SIGNED, &other, "_req1", NOW).err(),
            Some("saml_signature")
        );
        // During a rotation both certificates are listed, and either verifies.
        other.idp_certificates.extend(saml.idp_certificates.clone());
        assert!(check(SIGNED, &other, "_req1", NOW).is_ok());
        // Another audience, issuer or ACS; another request; too late.
        let mut audience = saml.clone();
        audience.sp_entity_id = "https://other.example.com".into();
        assert_eq!(
            check(SIGNED, &audience, "_req1", NOW).err(),
            Some("saml_audience")
        );
        let mut issuer = saml.clone();
        issuer.idp_entity_id = "http://evil.example.com".into();
        assert_eq!(
            check(SIGNED, &issuer, "_req1", NOW).err(),
            Some("saml_issuer")
        );
        let mut acs = saml.clone();
        acs.acs_url = "https://other.example.com/console/saml/acs".into();
        assert_eq!(
            check(SIGNED, &acs, "_req1", NOW).err(),
            Some("saml_recipient")
        );
        assert_eq!(
            check(SIGNED, &saml, "_req2", NOW).err(),
            Some("saml_replay")
        );
        assert_eq!(
            check(SIGNED, &saml, "_req1", 4_102_444_800 + 120).err(),
            Some("saml_expired")
        );
        // Encrypted assertions are refused with the fix.
        let encrypted = SIGNED.replace(
            "</samlp:Response>",
            "<saml:EncryptedAssertion/></samlp:Response>",
        );
        assert_eq!(
            check(&encrypted, &saml, "_req1", NOW).err(),
            Some("saml_encrypted")
        );
    }
}
