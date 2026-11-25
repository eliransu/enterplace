//! Requests captured from Codex CLI 0.166.0 (`codex exec`, default config with the multi_agent feature, and with it
//! off), carried to Anthropic, Gemini and Bedrock Converse through chat completions. IDs and paths are replaced.

use enterplace_core::{converse, gemini, responses, translate};
use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(name: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

#[test]
fn codex_requests_reach_anthropic_gemini_and_converse() -> TestResult {
    for name in ["codex-0.166.0-multi-agent.json", "codex-0.166.0.json"] {
        let request = fixture(name)?;
        let chat = responses::responses_to_chat_request(&request)?;
        for field in ["client_metadata", "store", "prompt_cache_key"] {
            assert!(chat.dropped.iter().any(|d| d == field), "{name}: {field}");
            assert!(chat.body.get(field).is_none(), "{name}: {field}");
        }
        assert!(
            chat.dropped
                .iter()
                .any(|d| d == "include: reasoning.encrypted_content")
        );
        let tools = chat.body["tools"].as_array().map_or(0, Vec::len);
        let declared: usize = request["tools"]
            .as_array()
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .map(|t| t["tools"].as_array().map_or(1, Vec::len))
            .sum();
        assert_eq!(
            tools, declared,
            "{name}: every tool, namespaced ones flattened"
        );
        if name.contains("multi-agent") {
            assert!(
                chat.namespaces
                    .get("multi_agent_v1__spawn_agent")
                    .is_some_and(|(ns, n)| ns == "multi_agent_v1" && n == "spawn_agent"),
                "{:?}",
                chat.namespaces
            );
        }
        let anthropic = translate::openai_to_anthropic_request(&chat.body)?;
        assert!(anthropic["system"].is_array() || anthropic["system"].is_string());
        assert_eq!(anthropic["tools"].as_array().map_or(0, Vec::len), tools);
        let (google, stream) = gemini::openai_to_gemini_request(&chat.body)?;
        assert!(stream);
        assert_eq!(
            google["tools"][0]["functionDeclarations"]
                .as_array()
                .map_or(0, Vec::len),
            tools
        );
        let (bedrock, stream) =
            converse::openai_to_converse_request(&chat.body, "amazon.nova-pro-v1:0")?;
        assert!(stream);
        assert_eq!(
            bedrock["toolConfig"]["tools"]
                .as_array()
                .map_or(0, Vec::len),
            tools
        );
    }
    Ok(())
}
