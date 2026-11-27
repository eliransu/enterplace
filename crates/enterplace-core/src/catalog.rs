//! The providers a policy can name with `preset: <id>` instead of writing their URL and kind by hand.
//! Every URL was read from the provider's own API documentation, linked in `docs`. A URL ends where the vendor's
//! `/v1` would (see `config::join`), so a chat request reaches `<url>/chat/completions`.

use crate::config::Kind;

/// One provider of the catalog.
#[derive(Clone, Copy, Debug)]
pub struct Preset {
    /// What a policy writes after `preset:`.
    pub id: &'static str,
    pub name: &'static str,
    pub kind: Kind,
    pub url: &'static str,
    /// A model server people run themselves: its URL is the server's default on this machine, so the policy needs
    /// `allow_private: true`, and a key only if the server was started with one.
    pub local: bool,
    /// The page of the provider's own documentation the URL was taken from.
    pub docs: &'static str,
}

impl Preset {
    /// The header the provider key goes in. It follows from the kind: Enterplace sends it as `config::Kind` says.
    pub fn key_header(&self) -> &'static str {
        match self.kind {
            Kind::Anthropic => "x-api-key",
            Kind::Gemini => "x-goog-api-key",
            Kind::Azure => "api-key",
            Kind::OpenAi
            | Kind::Vertex
            | Kind::VertexAnthropic
            | Kind::VertexOpenAi
            | Kind::Bedrock
            | Kind::BedrockConverse
            | Kind::Cohere
            | Kind::Watsonx
            | Kind::Replicate => "Authorization: Bearer",
            Kind::Demo => "none: answered inside Enterplace",
            Kind::Sagemaker => "AWS Signature Version 4",
        }
    }

    /// Whether the provider takes a key: "none" (the demo model, or AWS, which signs with its own credentials),
    /// "optional" (a server on this machine, or a cloud that signs in without one) or "required". It follows what
    /// `config` accepts for the kind.
    pub fn key_need(&self) -> &'static str {
        match self.kind {
            Kind::Demo => "none",
            k if k.aws() => "none",
            k if self.local || k.google_auth() || k == Kind::Azure => "optional",
            _ => "required",
        }
    }

    /// A URL with a placeholder host label in capitals (WORKSPACE, ACCOUNT): the provider must write its own url.
    pub fn needs_url(&self) -> bool {
        self.url
            .split_once("://")
            .and_then(|(_, rest)| rest.split('/').next())
            .is_some_and(|host| {
                host.split('.')
                    .any(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_uppercase()))
            })
    }
}

const fn native(
    id: &'static str,
    name: &'static str,
    kind: Kind,
    url: &'static str,
    docs: &'static str,
) -> Preset {
    Preset {
        id,
        name,
        kind,
        url,
        local: false,
        docs,
    }
}

const fn hosted(
    id: &'static str,
    name: &'static str,
    url: &'static str,
    docs: &'static str,
) -> Preset {
    Preset {
        id,
        name,
        kind: Kind::OpenAi,
        url,
        local: false,
        docs,
    }
}

const fn local(
    id: &'static str,
    name: &'static str,
    url: &'static str,
    docs: &'static str,
) -> Preset {
    Preset {
        id,
        name,
        kind: Kind::OpenAi,
        url,
        local: true,
        docs,
    }
}

/// The catalog, sorted by id.
pub const PRESETS: &[Preset] = &[
    hosted(
        "302ai",
        "302.AI",
        "https://api.302.ai/v1",
        "https://doc.302.ai/147522039e0",
    ),
    hosted(
        "abacus",
        "Abacus.AI RouteLLM",
        "https://routellm.abacus.ai/v1",
        "https://abacus.ai/help/developer-platform/route-llm/chat-completions/",
    ),
    hosted(
        "ai21",
        "AI21 Studio",
        "https://api.ai21.com/studio/v1",
        "https://docs.ai21.com/reference/jamba-1-6-api-ref",
    ),
    hosted(
        "aihubmix",
        "AIHubMix",
        "https://aihubmix.com/v1",
        "https://docs.aihubmix.com/en/quick-start",
    ),
    hosted(
        "aimlapi",
        "AI/ML API",
        "https://api.aimlapi.com/v1",
        "https://docs.aimlapi.com/quickstart/setting-up",
    ),
    hosted(
        "akashml",
        "AkashML",
        "https://api.akashml.com/v1",
        "https://akashml.com/docs/guides/akash-chat",
    ),
    Preset {
        id: "anthropic",
        name: "Anthropic",
        kind: Kind::Anthropic,
        url: "https://api.anthropic.com/v1",
        local: false,
        docs: "https://platform.claude.com/docs/en/api/overview",
    },
    local(
        "aphrodite",
        "Aphrodite Engine",
        "http://127.0.0.1:2242/v1",
        "https://sonar.dphn.ai/serving/openai/",
    ),
    hosted(
        "arcee",
        "Arcee AI",
        "https://api.arcee.ai/api/v1",
        "https://docs.arcee.ai/",
    ),
    hosted(
        "atlascloud",
        "Atlas Cloud",
        "https://api.atlascloud.ai/v1",
        "https://atlascloud.ai/docs/en/models/llm",
    ),
    hosted(
        "avian",
        "Avian",
        "https://api.avian.io/v1",
        "https://avian.io/docs",
    ),
    hosted(
        "baseten",
        "Baseten Model APIs",
        "https://inference.baseten.co/v1",
        "https://docs.baseten.co/development/model-apis/overview",
    ),
    hosted(
        "berget",
        "Berget AI",
        "https://api.berget.ai/v1",
        "https://api.berget.ai/",
    ),
    hosted(
        "byteplus",
        "BytePlus ModelArk",
        "https://ark.ap-southeast.bytepluses.com/api/v3",
        "https://docs.byteplus.com/en/docs/ModelArk/1399008",
    ),
    hosted(
        "cerebras",
        "Cerebras",
        "https://api.cerebras.ai/v1",
        "https://inference-docs.cerebras.ai/api-reference/chat-completions",
    ),
    hosted(
        "chutes",
        "Chutes",
        "https://llm.chutes.ai/v1",
        "https://chutes.ai/llms.txt",
    ),
    hosted(
        "clarifai",
        "Clarifai",
        "https://api.clarifai.com/v2/ext/openai/v1",
        "https://docs.clarifai.com/getting-started/quickstart/",
    ),
    hosted(
        "cloudrift",
        "CloudRift",
        "https://inference.cloudrift.ai/v1",
        "https://www.cloudrift.ai/inference",
    ),
    hosted(
        "cohere",
        "Cohere (Compatibility API)",
        "https://api.cohere.ai/compatibility/v1",
        "https://docs.cohere.com/docs/compatibility-api",
    ),
    native(
        "cohere-native",
        "Cohere (v2 API: chat, embed, rerank)",
        Kind::Cohere,
        "https://api.cohere.com/v2",
        "https://docs.cohere.com/reference/chat",
    ),
    hosted(
        "cometapi",
        "CometAPI",
        "https://api.cometapi.com/v1",
        "https://apidoc.cometapi.com/",
    ),
    hosted(
        "cortecs",
        "Cortecs",
        "https://api.cortecs.ai/v1",
        "https://docs.cortecs.ai/serverless-inference/api/chat-completions",
    ),
    hosted(
        "databricks",
        "Databricks Model Serving (write your workspace URL)",
        "https://WORKSPACE.cloud.databricks.com/serving-endpoints",
        "https://docs.databricks.com/aws/en/machine-learning/model-serving/score-foundation-models",
    ),
    hosted(
        "deepinfra",
        "DeepInfra",
        "https://api.deepinfra.com/v1/openai",
        "https://docs.deepinfra.com/chat/overview",
    ),
    hosted(
        "deepseek",
        "DeepSeek",
        "https://api.deepseek.com/v1",
        "https://api-docs.deepseek.com/",
    ),
    native(
        "demo",
        "Enterplace demo model (answered inside Enterplace, no key, free)",
        Kind::Demo,
        "https://demo.enterplace.invalid/v1",
        "https://docs.enterplace.dev/getting-started/quickstart/",
    ),
    hosted(
        "digitalocean",
        "DigitalOcean Gradient",
        "https://inference.do-ai.run/v1",
        "https://docs.digitalocean.com/products/inference/how-to/use-chat-completions-api/",
    ),
    local(
        "docker-model-runner",
        "Docker Model Runner",
        "http://localhost:12434/engines/v1",
        "https://docs.docker.com/ai/model-runner/api-reference/",
    ),
    hosted(
        "fastrouter",
        "FastRouter",
        "https://api.fastrouter.ai/api/v1",
        "https://docs.fastrouter.ai/api-reference/chat-completions",
    ),
    hosted(
        "featherless",
        "Featherless AI",
        "https://api.featherless.ai/v1",
        "https://featherless.ai/docs/api-overview-and-common-options",
    ),
    hosted(
        "fireworks",
        "Fireworks AI",
        "https://api.fireworks.ai/inference/v1",
        "https://docs.fireworks.ai/api-reference/post-chatcompletions",
    ),
    hosted(
        "friendli",
        "FriendliAI Serverless",
        "https://api.friendli.ai/serverless/v1",
        "https://friendli.ai/docs/openapi/serverless/chat-completions",
    ),
    Preset {
        id: "gemini",
        name: "Google Gemini API",
        kind: Kind::Gemini,
        url: "https://generativelanguage.googleapis.com/v1beta",
        local: false,
        docs: "https://aistudio.google.com/api-reference/generate-content",
    },
    hosted(
        "gemini-openai",
        "Google Gemini API (OpenAI compatibility)",
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "https://aistudio.google.com/docs/openai",
    ),
    hosted(
        "gitee-ai",
        "Gitee AI (MoArk)",
        "https://api.moark.com/v1",
        "https://moark.com/docs/products/apis/texts/text-generation",
    ),
    hosted(
        "gmi",
        "GMI Cloud",
        "https://api.gmi-serving.com/v1",
        "https://docs.gmicloud.ai/inference-engine/api-reference/llm-api-reference",
    ),
    local(
        "gpt4all",
        "GPT4All",
        "http://localhost:4891/v1",
        "https://docs.gpt4all.io/gpt4all_api_server/home.html",
    ),
    hosted(
        "groq",
        "Groq",
        "https://api.groq.com/openai/v1",
        "https://console.groq.com/docs/api-reference",
    ),
    hosted(
        "heroku",
        "Heroku Managed Inference",
        "https://us.inference.heroku.com/v1",
        "https://devcenter.heroku.com/articles/ai-integrations-vercel",
    ),
    hosted(
        "huggingface",
        "Hugging Face Inference Providers",
        "https://router.huggingface.co/v1",
        "https://huggingface.co/docs/inference-providers/index",
    ),
    hosted(
        "hunyuan",
        "Tencent Hunyuan",
        "https://api.hunyuan.cloud.tencent.com/v1",
        "https://cloud.tencent.com/document/product/1729/111007",
    ),
    hosted(
        "hyperbolic",
        "Hyperbolic",
        "https://api.hyperbolic.ai/inference/v1",
        "https://hyperbolic.ai/docs/inference/quickstart.md",
    ),
    hosted(
        "inference-net",
        "Inference.net",
        "https://api.inference.net/v1",
        "https://docs.inference.net/quickstart",
    ),
    hosted(
        "infermatic",
        "Infermatic",
        "https://api.totalgpt.ai/v1",
        "https://ui.infermatic.ai/docs",
    ),
    hosted(
        "infini-ai",
        "Infini-AI",
        "https://cloud.infini-ai.com/maas/v1",
        "https://docs.infini-ai.com/gen-studio/api/get-started/",
    ),
    hosted(
        "io-intelligence",
        "IO Intelligence (io.net)",
        "https://api.intelligence.io.solutions/api/v1",
        "https://io.net/docs/reference/ai-models/create-chat-completion",
    ),
    hosted(
        "ionos",
        "IONOS AI Model Hub",
        "https://openai.inference.de-txl.ionos.com/v1",
        "https://docs.ionos.com/cloud/ai/ai-model-hub/how-tos/text-generation",
    ),
    local(
        "jan",
        "Jan",
        "http://127.0.0.1:1337/v1",
        "https://docs.jan.ai/desktop/api-server",
    ),
    hosted(
        "jina-deepsearch",
        "Jina DeepSearch",
        "https://deepsearch.jina.ai/v1",
        "https://jina.ai/deepsearch/",
    ),
    hosted(
        "kilo",
        "Kilo Gateway",
        "https://ai-gateway.kilo.ai/api/v1",
        "https://kilo.ai/docs/gateway/authentication",
    ),
    local(
        "koboldcpp",
        "KoboldCpp",
        "http://localhost:5001/v1",
        "https://github.com/LostRuins/koboldcpp/wiki",
    ),
    hosted(
        "krutrim",
        "Krutrim Cloud",
        "https://cloud.olakrutrim.com/v1",
        "https://docs.cloud.olakrutrim.com/basics/ai-studio/ai-jobs/inferencing",
    ),
    local(
        "lemonade",
        "Lemonade Server",
        "http://localhost:13305/v1",
        "https://lemonade-server.ai/docs/api/openai/",
    ),
    hosted(
        "lingyiwanwu",
        "01.AI Lingyiwanwu",
        "https://api.lingyiwanwu.com/v1",
        "https://platform.lingyiwanwu.com/docs/api-reference",
    ),
    local(
        "llama-swap",
        "llama-swap",
        "http://localhost:8080/v1",
        "https://github.com/mostlygeek/llama-swap/blob/main/README.md",
    ),
    local(
        "llamacpp",
        "llama.cpp server",
        "http://127.0.0.1:9931/v1",
        "https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md",
    ),
    local(
        "llamafile",
        "llamafile",
        "http://127.0.0.1:8080/v1",
        "https://docs.mozilla.ai/llamafile/using-llamafile/api",
    ),
    local(
        "lmdeploy",
        "LMDeploy",
        "http://localhost:23333/v1",
        "https://lmdeploy.readthedocs.io/en/latest/llm/api_server.html",
    ),
    local(
        "lmstudio",
        "LM Studio",
        "http://localhost:1234/v1",
        "https://lmstudio.ai/docs/developer/openai-compat",
    ),
    local(
        "localai",
        "LocalAI",
        "http://localhost:8080/v1",
        "https://localai.io/docs/basics/getting_started/",
    ),
    hosted(
        "longcat",
        "Meituan LongCat",
        "https://api.longcat.chat/openai/v1",
        "https://longcat.chat/platform/docs/",
    ),
    hosted(
        "martian",
        "Martian",
        "https://api.withmartian.com/v1",
        "https://docs.withmartian.com/",
    ),
    hosted(
        "meta",
        "Meta Model API",
        "https://api.meta.ai/v1",
        "https://dev.meta.ai/docs/quickstart",
    ),
    hosted(
        "minimax",
        "MiniMax",
        "https://api.minimax.io/v1",
        "https://platform.minimax.io/docs/api-reference/text-chat-openai",
    ),
    hosted(
        "minimax-cn",
        "MiniMax (China)",
        "https://api.minimax.cn/v1",
        "https://platform.minimax.cn/docs/api-reference/text-chat-openai",
    ),
    hosted(
        "mistral",
        "Mistral AI",
        "https://api.mistral.ai/v1",
        "https://docs.mistral.ai/api/",
    ),
    local(
        "mistralrs",
        "mistral.rs",
        "http://localhost:1234/v1",
        "https://docs.mistralrs.dev/quickstart/",
    ),
    local(
        "mlx-lm",
        "MLX LM server",
        "http://localhost:8080/v1",
        "https://github.com/ml-explore/mlx-lm/blob/main/mlx_lm/SERVER.md",
    ),
    hosted(
        "modelscope",
        "ModelScope API-Inference",
        "https://api-inference.modelscope.cn/v1",
        "https://modelscope.cn/headlines/article/960",
    ),
    hosted(
        "moonshot",
        "Moonshot AI (Kimi)",
        "https://api.moonshot.ai/v1",
        "https://platform.kimi.ai/docs/api/chat",
    ),
    hosted(
        "moonshot-cn",
        "Moonshot AI (China)",
        "https://api.moonshot.cn/v1",
        "https://platform.kimi.com/docs/api/chat",
    ),
    hosted(
        "morph",
        "Morph",
        "https://api.morphllm.com/v1",
        "https://docs.morphllm.com/api-reference/endpoint/apply",
    ),
    hosted(
        "nebius",
        "Nebius Token Factory",
        "https://api.tokenfactory.nebius.com/v1",
        "https://docs.tokenfactory.nebius.com/",
    ),
    local(
        "nexa",
        "Nexa SDK server",
        "http://127.0.0.1:18181/v1",
        "https://geniex.aihub.qualcomm.com/en/run/cli/local-server",
    ),
    hosted(
        "nous",
        "Nous Research",
        "https://inference-api.nousresearch.com/v1",
        "https://hermes-agent.nousresearch.com/docs/integrations/providers",
    ),
    hosted(
        "novita",
        "Novita AI",
        "https://api.novita.ai/openai/v1",
        "https://docs.novita.ai/guides/llm-api",
    ),
    hosted(
        "nscale",
        "Nscale",
        "https://inference.api.nscale.com/v1",
        "https://docs.nscale.com/api-reference/inference/create-chat-completion",
    ),
    hosted(
        "nvidia",
        "NVIDIA NIM",
        "https://integrate.api.nvidia.com/v1",
        "https://docs.api.nvidia.com/nim/reference/meta-llama-3_1-8b-infer",
    ),
    hosted(
        "oci",
        "Oracle OCI Generative AI (us-chicago-1, API key; write your region's URL for another)",
        "https://inference.generativeai.us-chicago-1.oci.oraclecloud.com/20231130/actions/v1",
        "https://docs.oracle.com/iaas/Content/generative-ai/api-keys.htm",
    ),
    local(
        "ollama",
        "Ollama",
        "http://localhost:11434/v1",
        "https://docs.ollama.com/api/openai-compatibility",
    ),
    hosted(
        "ollama-cloud",
        "Ollama Cloud",
        "https://ollama.com/v1",
        "https://docs.ollama.com/api/openai-compatibility",
    ),
    hosted(
        "openai",
        "OpenAI",
        "https://api.openai.com/v1",
        "https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create",
    ),
    hosted(
        "opencode-zen",
        "OpenCode Zen",
        "https://opencode.ai/inference/openai/v1",
        "https://opencode.ai/docs/zen/",
    ),
    local(
        "openllm",
        "OpenLLM",
        "http://localhost:3000/v1",
        "https://github.com/bentoml/OpenLLM/blob/main/README.md",
    ),
    hosted(
        "openrouter",
        "OpenRouter",
        "https://openrouter.ai/api/v1",
        "https://openrouter.ai/docs/api/reference/overview",
    ),
    hosted(
        "ovhcloud",
        "OVHcloud AI Endpoints",
        "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1",
        "https://docs.ovhcloud.com/en/guides/public-cloud/ai-machine-learning/ai-endpoints-getting-started",
    ),
    hosted(
        "parasail",
        "Parasail",
        "https://api.parasail.io/v1",
        "https://docs.parasail.io/parasail-docs/quickstart/serverless",
    ),
    hosted(
        "perplexity",
        "Perplexity (Orchestrator API)",
        "https://api.perplexity.ai/orchestrator/v1",
        "https://docs.perplexity.ai/docs/router/quickstart",
    ),
    hosted(
        "poe",
        "Poe",
        "https://api.poe.com/v1",
        "https://creator.poe.com/docs/external-applications/openai-compatible-api",
    ),
    hosted(
        "ppio",
        "PPIO",
        "https://api.ppio.com/openai/v1",
        "https://ppio.com/docs/models/reference-llm",
    ),
    hosted(
        "qianfan",
        "Baidu Qianfan",
        "https://qianfan.baidubce.com/v2",
        "https://cloud.baidu.com/doc/qianfan-api/s/3m7of64lb",
    ),
    hosted(
        "qiniu",
        "Qiniu AI",
        "https://api.qnaigc.com/v1",
        "https://developer-doc.qiniu.com/products/aitokenapi/inference-api/1-real-time-ai-interface-api",
    ),
    local(
        "ramalama",
        "RamaLama",
        "http://127.0.0.1:8080/v1",
        "https://github.com/containers/ramalama/blob/main/docs/ramalama-serve.1.md",
    ),
    hosted(
        "regolo",
        "Regolo.ai",
        "https://api.regolo.ai/v1",
        "https://docs.regolo.ai/models/families/completions/",
    ),
    hosted(
        "reka",
        "Reka",
        "https://api.reka.ai/v1",
        "https://docs.reka.ai/chat/overview",
    ),
    native(
        "replicate",
        "Replicate",
        Kind::Replicate,
        "https://api.replicate.com/v1",
        "https://replicate.com/docs/reference/http",
    ),
    hosted(
        "requesty",
        "Requesty",
        "https://router.requesty.ai/v1",
        "https://docs.requesty.ai/quickstart",
    ),
    native(
        "sagemaker",
        "Amazon SageMaker endpoints (us-east-1; set region: for another)",
        Kind::Sagemaker,
        "https://runtime.sagemaker.us-east-1.amazonaws.com/endpoints",
        "https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_runtime_InvokeEndpoint.html",
    ),
    hosted(
        "sambanova",
        "SambaNova Cloud",
        "https://api.sambanova.ai/v1",
        "https://docs.sambanova.ai/docs/api-reference/chat-completions/create-chat-based-completion",
    ),
    hosted(
        "sarvam",
        "Sarvam AI",
        "https://api.sarvam.ai/v1",
        "https://docs.sarvam.ai/api-reference-docs/authentication",
    ),
    hosted(
        "scaleway",
        "Scaleway Generative APIs",
        "https://api.scaleway.ai/v1",
        "https://www.scaleway.com/en/docs/generative-apis/api-cli/using-chat-api/",
    ),
    local(
        "sglang",
        "SGLang",
        "http://127.0.0.1:30000/v1",
        "https://docs.sglang.io/advanced_features/server_arguments.html",
    ),
    hosted(
        "siliconflow",
        "SiliconFlow",
        "https://api.siliconflow.com/v1",
        "https://docs.siliconflow.com/en/api-reference/chat-completions/chat-completions",
    ),
    hosted(
        "siliconflow-cn",
        "SiliconFlow (China)",
        "https://api.siliconflow.cn/v1",
        "https://docs.siliconflow.cn/cn/api-reference/chat-completions/chat-completions",
    ),
    hosted(
        "snowflake",
        "Snowflake Cortex REST API (write your account URL)",
        "https://ACCOUNT.snowflakecomputing.com/api/v2/cortex/v1",
        "https://docs.snowflake.com/en/user-guide/snowflake-cortex/open_ai_sdk",
    ),
    hosted(
        "spark",
        "iFlytek Spark",
        "https://spark-api-open.xf-yun.com/v1",
        "https://www.xfyun.cn/doc/spark/HTTP%E8%B0%83%E7%94%A8%E6%96%87%E6%A1%A3.html",
    ),
    hosted(
        "stepfun",
        "StepFun",
        "https://api.stepfun.com/v1",
        "https://platform.stepfun.com/docs/api-reference/chat/chat-completion-create",
    ),
    hosted(
        "synthetic",
        "Synthetic",
        "https://api.synthetic.new/openai/v1",
        "https://dev.synthetic.new/docs/api/overview",
    ),
    local(
        "tabbyapi",
        "TabbyAPI",
        "http://127.0.0.1:5000/v1",
        "https://github.com/theroyallab/tabbyAPI/blob/main/config_sample.yml",
    ),
    hosted(
        "telnyx",
        "Telnyx Inference",
        "https://api.telnyx.com/v2/ai/openai",
        "https://developers.telnyx.com/api-reference/openai-chat/create-a-chat-completion-openai-compatible",
    ),
    local(
        "tensorrt-llm",
        "TensorRT-LLM (trtllm-serve)",
        "http://localhost:8000/v1",
        "https://nvidia.github.io/TensorRT-LLM/commands/trtllm-serve/trtllm-serve.html",
    ),
    local(
        "text-generation-webui",
        "text-generation-webui",
        "http://127.0.0.1:5000/v1",
        "https://github.com/oobabooga/text-generation-webui/blob/main/docs/12%20-%20OpenAI%20API.md",
    ),
    local(
        "tgi",
        "Text Generation Inference",
        "http://localhost:3000/v1",
        "https://huggingface.co/docs/text-generation-inference/messages_api",
    ),
    hosted(
        "together",
        "Together AI",
        "https://api.together.ai/v1",
        "https://docs.together.ai/reference/chat-completions-1",
    ),
    local(
        "triton",
        "NVIDIA Triton Inference Server (OpenAI-compatible frontend)",
        "http://localhost:9000/v1",
        "https://github.com/triton-inference-server/server/blob/main/python/openai/README.md",
    ),
    hosted(
        "typesafe",
        "TypeSafe (Jev decision models, native API through passthrough)",
        "https://api.typesafe.ai/v1",
        "https://docs.typesafe.ai/api",
    ),
    hosted(
        "upstage",
        "Upstage",
        "https://api.upstage.ai/v1",
        "https://console.upstage.ai/docs/capabilities/chat",
    ),
    hosted(
        "venice",
        "Venice.ai",
        "https://api.venice.ai/api/v1",
        "https://docs.venice.ai/api-reference/endpoint/chat/completions",
    ),
    hosted(
        "vercel",
        "Vercel AI Gateway",
        "https://ai-gateway.vercel.sh/v1",
        "https://vercel.com/docs/ai-gateway/sdks-and-apis/openai-chat-completions",
    ),
    local(
        "vllm",
        "vLLM",
        "http://localhost:8000/v1",
        "https://docs.vllm.ai/en/latest/getting_started/quickstart.html",
    ),
    hosted(
        "volcengine",
        "Volcengine Ark",
        "https://ark.cn-beijing.volces.com/api/v3",
        "https://docs.volcengine.com/docs/82379/1298459",
    ),
    hosted(
        "vultr",
        "Vultr Serverless Inference",
        "https://api.vultrinference.com/v1",
        "https://docs.vultr.com/how-to-use-vultr-serverless-inference-in-nodejs",
    ),
    hosted(
        "wandb",
        "Weights & Biases Inference",
        "https://api.inference.wandb.ai/v1",
        "https://docs.coreweave.com/inference/api-reference/chat-completions",
    ),
    native(
        "watsonx",
        "IBM watsonx.ai (us-south; write your region's URL for another)",
        Kind::Watsonx,
        "https://us-south.ml.cloud.ibm.com/ml/v1",
        "https://cloud.ibm.com/apidocs/watsonx-ai#text-chat",
    ),
    hosted(
        "xai",
        "xAI",
        "https://api.x.ai/v1",
        "https://docs.x.ai/developers/model-capabilities/legacy/chat-completions",
    ),
    local(
        "xinference",
        "Xorbits Inference",
        "http://127.0.0.1:9997/v1",
        "https://github.com/xorbitsai/inference/blob/main/README.md",
    ),
    hosted(
        "zai",
        "Z.ai",
        "https://api.z.ai/api/paas/v4",
        "https://docs.z.ai/api-reference/llm/chat-completion",
    ),
    hosted(
        "zai-coding",
        "Z.ai GLM Coding Plan",
        "https://api.z.ai/api/coding/paas/v4",
        "https://docs.z.ai/devpack/tool/others",
    ),
    hosted(
        "zenmux",
        "ZenMux",
        "https://zenmux.ai/api/v1",
        "https://zenmux.ai/docs/api/openai/create-chat-completion.html",
    ),
    hosted(
        "zhipu",
        "Zhipu BigModel (China)",
        "https://open.bigmodel.cn/api/paas/v4",
        "https://docs.bigmodel.cn/api-reference/%E6%A8%A1%E5%9E%8B-api/%E5%AF%B9%E8%AF%9D%E8%A1%A5%E5%85%A8",
    ),
];

/// The catalog entry a policy names with `preset: <id>`.
/// The providers `enterplace start` and the console's Connect a model set up, with the models people use most from each.
/// A policy lists exact model names, so another provider is set up with `enterplace init` or in the policy.
pub const START_PROVIDERS: &[(&str, &[&str])] = &[
    (
        "openai",
        &["gpt-5", "gpt-5-mini", "gpt-5-codex", "gpt-4o-mini"],
    ),
    ("anthropic", &["claude-sonnet-5-5", "claude-haiku-5-5"]),
    ("gemini", &["gemini-2.5-pro", "gemini-2.5-flash"]),
];

/// Models the console fills in when a provider is picked from the catalog, for the providers outside
/// [`START_PROVIDERS`]: each one's flagship and a cheaper model, read from its own model list or docs (November
/// 2026). A suggestion the admin edits before saving; a provider not listed here starts with an empty list.
pub const DEFAULT_MODELS: &[(&str, &[&str])] = &[
    (
        "302ai",
        &[
            "gpt-6.2-sol",
            "claude-fable-5-2",
            "claude-haiku-5-5",
            "kimi-k3.1-pro",
        ],
    ),
    (
        "abacus",
        &[
            "route-llm",
            "claude-sonnet-5-5",
            "gpt-6.2-sol",
            "gemini-3.8-flash",
        ],
    ),
    ("ai21", &["jamba-large", "jamba-mini"]),
    (
        "aihubmix",
        &["gpt-6.2-sol", "qwen4-max", "kimi-k3.1-pro", "qwen3.8-27b"],
    ),
    (
        "aimlapi",
        &[
            "openai/gpt-6.2-sol",
            "anthropic/claude-sonnet-5-5",
            "deepseek/deepseek-v4-pro",
            "openai/gpt-5.4-nano",
        ],
    ),
    (
        "akashml",
        &[
            "zai-org/GLM-5.3",
            "moonshotai/Kimi-K3.1-Pro",
            "openai/gpt-oss-120b",
            "openai/gpt-oss-20b",
        ],
    ),
    (
        "atlascloud",
        &[
            "qwen/qwen3.6-plus",
            "deepseek-ai/deepseek-v3.2",
            "qwen/qwen3.6-35b-a3b",
        ],
    ),
    (
        "avian",
        &[
            "deepseek/deepseek-v4-pro-0813",
            "z-ai/glm-5.3",
            "moonshotai/kimi-k3",
            "deepseek/deepseek-v4.1-flash",
        ],
    ),
    (
        "baseten",
        &[
            "deepseek-ai/DeepSeek-V4-Pro-0813",
            "zai-org/GLM-5.3",
            "moonshotai/Kimi-K3",
            "deepseek-ai/DeepSeek-V4.1-Flash",
        ],
    ),
    (
        "berget",
        &[
            "moonshotai/Kimi-K3.1-Pro",
            "zai-org/GLM-5.3-Flash",
            "google/gemma-4-31B-it",
            "mistralai/Mistral-Small-3.2-24B-Instruct-2506",
        ],
    ),
    ("cerebras", &["gpt-oss-120b", "qwen-3.8-27b"]),
    (
        "chutes",
        &[
            "deepseek-ai/DeepSeek-V4-Pro-0813",
            "zai-org/GLM-5.3",
            "moonshotai/Kimi-K3-TEE",
            "Qwen/Qwen3.8-27B-TEE",
        ],
    ),
    (
        "cohere",
        &[
            "command-a-plus-05-2026",
            "command-a-03-2025",
            "command-r7b-12-2024",
        ],
    ),
    (
        "cohere-native",
        &[
            "command-a-plus-05-2026",
            "command-a-03-2025",
            "command-r7b-12-2024",
        ],
    ),
    (
        "cometapi",
        &[
            "gpt-6.2-astra",
            "claude-fable-5-2",
            "gemini-4-neon",
            "deepseek-v4.1-flash",
        ],
    ),
    (
        "cortecs",
        &[
            "claude-opus-5.5",
            "gpt-6.2-sol",
            "gemini-4-neon",
            "deepseek-v4.1-flash",
        ],
    ),
    (
        "deepinfra",
        &[
            "deepseek-ai/DeepSeek-V4.1-Flash",
            "zai-org/GLM-5.3",
            "moonshotai/Kimi-K3.1-Pro",
            "google/gemma-4-31B-it",
        ],
    ),
    ("deepseek", &["deepseek-v4-pro", "deepseek-flash"]),
    ("demo", &["enterplace-demo"]),
    (
        "digitalocean",
        &[
            "anthropic-claude-opus-5.5",
            "openai-gpt-6.2-sol",
            "deepseek-v4.1-flash",
            "glm-5.3",
        ],
    ),
    (
        "fastrouter",
        &[
            "anthropic/claude-opus-5.5",
            "openai/gpt-6.2-astra",
            "google/gemini-4-neon",
            "deepseek/deepseek-v4.1-flash",
        ],
    ),
    (
        "featherless",
        &[
            "deepseek-ai/DeepSeek-V4-Pro",
            "moonshotai/Kimi-K3.1-Pro",
            "zai-org/GLM-5.3",
            "deepseek-ai/DeepSeek-V4.1-Flash",
        ],
    ),
    (
        "fireworks",
        &[
            "accounts/fireworks/models/kimi-k3p1-pro",
            "accounts/fireworks/models/glm-5p3",
        ],
    ),
    (
        "friendli",
        &[
            "zai-org/GLM-5.3",
            "zai-org/GLM-5.3-Flash",
            "google/gemma-4-31B-it",
        ],
    ),
    (
        "gemini-openai",
        &["gemini-4-neon", "gemini-3.8-flash", "gemini-3.5-flash-lite"],
    ),
    (
        "gitee-ai",
        &[
            "kimi-k3.1-pro",
            "GLM-5.3",
            "deepseek-v4.1-flash",
            "qwen3.8-max",
        ],
    ),
    (
        "gmi",
        &[
            "deepseek-ai/DeepSeek-V4-Pro",
            "openai/gpt-5.5",
            "anthropic/claude-sonnet-4.6",
            "deepseek-ai/DeepSeek-V4-Flash",
        ],
    ),
    (
        "groq",
        &[
            "openai/gpt-oss-120b",
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "openai/gpt-oss-20b",
        ],
    ),
    (
        "heroku",
        &[
            "claude-opus-5-5",
            "claude-sonnet-5-5",
            "claude-haiku-5-5",
            "gpt-oss-120b",
        ],
    ),
    (
        "huggingface",
        &["deepseek-ai/DeepSeek-V4.1-Flash", "deepseek-ai/DeepSeek-R1"],
    ),
    ("hunyuan", &["hunyuan-turbos-latest", "hunyuan-lite"]),
    (
        "hyperbolic",
        &["glm-5.3", "glm-5.3-flash", "deepseek-v4.1-flash", "kimi-k3"],
    ),
    (
        "inference-net",
        &["glm-5.2", "gpt-5-mini", "claude-haiku-4-5"],
    ),
    (
        "infini-ai",
        &["deepseek-v4-pro", "deepseek-v4-flash", "kimi-k2.6"],
    ),
    (
        "ionos",
        &[
            "openai/gpt-oss-120b",
            "meta-llama/Llama-3.3-70B-Instruct",
            "Qwen/Qwen3.5-9B",
        ],
    ),
    ("jina-deepsearch", &["jina-deepsearch-v1"]),
    (
        "kilo",
        &[
            "anthropic/claude-sonnet-4.6",
            "openai/gpt-5.4-mini",
            "kilo-auto/frontier",
        ],
    ),
    ("longcat", &["LongCat-2.5"]),
    ("meta", &["muse-spark-1.3", "muse-ember-1.0"]),
    ("minimax", &["MiniMax-M3", "MiniMax-M3.1-Flash"]),
    ("minimax-cn", &["MiniMax-M3", "MiniMax-M3.1-Flash"]),
    (
        "mistral",
        &[
            "mistral-large-4-0",
            "mistral-small-latest",
            "ministral-8b-latest",
        ],
    ),
    (
        "modelscope",
        &[
            "deepseek-ai/DeepSeek-V4-Pro",
            "Qwen/Qwen3.8-27B",
            "deepseek-ai/DeepSeek-V4.1-Flash",
        ],
    ),
    (
        "moonshot",
        &["kimi-k3.1-pro", "kimi-k3.1-pro-highspeed", "kimi-k3"],
    ),
    (
        "moonshot-cn",
        &["kimi-k3.1-pro", "kimi-k3.1-pro-highspeed", "kimi-k3"],
    ),
    ("morph", &["morph-v3-large", "morph-v3-fast", "auto"]),
    (
        "nebius",
        &[
            "moonshotai/Kimi-K3.1-Pro",
            "zai-org/GLM-5.3",
            "deepseek-ai/DeepSeek-V4.1-Flash-1017",
            "Qwen/Qwen3.8-27B",
        ],
    ),
    (
        "nous",
        &[
            "anthropic/claude-sonnet-5.5",
            "openai/gpt-6.2-sol",
            "google/gemini-3.8-flash",
        ],
    ),
    (
        "novita",
        &[
            "moonshotai/kimi-k3.1-pro",
            "zai-org/glm-5.3",
            "deepseek/deepseek-v4.1-flash",
            "qwen/qwen3.8-flash",
        ],
    ),
    (
        "nvidia",
        &[
            "moonshotai/kimi-k3.1-pro",
            "mistralai/mistral-large-4-1t-a52b",
            "z-ai/glm-5.3-flash",
            "nvidia/nemotron-3.5-lightning-30b-a3b",
        ],
    ),
    (
        "ollama-cloud",
        &[
            "kimi-k3.1-pro",
            "glm-5.3",
            "deepseek-v4.1-flash",
            "gpt-oss:20b",
        ],
    ),
    (
        "opencode-zen",
        &[
            "claude-sonnet-5-5",
            "gpt-6.2-sol",
            "claude-haiku-5-5",
            "gemini-3.8-flash",
        ],
    ),
    (
        "openrouter",
        &[
            "anthropic/claude-sonnet-5.5",
            "openai/gpt-6.2-sol",
            "anthropic/claude-haiku-5.5",
            "google/gemini-3.8-flash",
        ],
    ),
    (
        "ovhcloud",
        &[
            "Qwen3.5-397B-A17B",
            "Meta-Llama-3_3-70B-Instruct",
            "gpt-oss-120b",
            "Mistral-Small-3.2-24B-Instruct-2506",
        ],
    ),
    (
        "parasail",
        &[
            "parasail-kimi-k3",
            "parasail-glm-53",
            "parasail-deepseek-v4-flash",
            "parasail-qwen38-27b",
        ],
    ),
    (
        "perplexity",
        &[
            "perplexity/glm-5.3",
            "perplexity/glm-5.3-flash",
            "xai/grok-4.7",
            "openai/gpt-6-luna",
        ],
    ),
    (
        "poe",
        &[
            "Claude-Opus-4.7",
            "Claude-Sonnet-4.6",
            "GPT-5.4",
            "Gemini-3.1-Pro",
        ],
    ),
    (
        "ppio",
        &[
            "deepseek/deepseek-v4-pro",
            "deepseek/deepseek-v4.1-flash",
            "zai-org/glm-5.3",
            "qwen/qwen3.8-max",
        ],
    ),
    (
        "qianfan",
        &["ernie-5.1", "ernie-light-dt-1.0", "deepseek-v4-flash"],
    ),
    ("regolo", &["Llama-3.3-70B-Instruct", "gpt-oss-120b"]),
    ("reka", &["reka-flash-3", "reka-edge-2603"]),
    (
        "replicate",
        &[
            "openai/gpt-5.2",
            "anthropic/claude-opus-5.5",
            "google/gemini-3.1-pro",
            "openai/gpt-5-mini",
        ],
    ),
    (
        "requesty",
        &["openai/gpt-6-luna", "deepseek/deepseek-v4.1-flash"],
    ),
    ("sarvam", &["sarvam-105b", "sarvam-105b-conversations"]),
    (
        "siliconflow",
        &[
            "deepseek-ai/DeepSeek-V4-Pro",
            "deepseek-ai/DeepSeek-V4-Flash",
            "zai-org/GLM-5.1",
            "Qwen/Qwen3.6-35B-A3B",
        ],
    ),
    (
        "siliconflow-cn",
        &[
            "deepseek-ai/DeepSeek-V4-Flash",
            "deepseek-ai/DeepSeek-V3.2",
            "Pro/zai-org/GLM-5.1",
            "Qwen/Qwen3.6-27B",
        ],
    ),
    (
        "snowflake",
        &[
            "claude-sonnet-4-6",
            "claude-haiku-4-5",
            "openai-gpt-5.2",
            "openai-gpt-5-mini",
        ],
    ),
    ("spark", &["4.0Ultra", "pro-128k", "lite"]),
    ("stepfun", &["step-3.7-flash", "step-3.5-flash"]),
    (
        "synthetic",
        &[
            "hf:zai-org/GLM-5.3-Flash",
            "hf:moonshotai/Kimi-K3.1-Pro",
            "hf:deepseek-ai/DeepSeek-V4.1-Flash-1017",
            "hf:openai/gpt-oss-120b",
        ],
    ),
    (
        "telnyx",
        &[
            "zai-org/GLM-5.3",
            "zai-org/GLM-5.3-Flash",
            "moonshotai/Kimi-K3",
            "Qwen/Qwen3.8-27B",
        ],
    ),
    (
        "together",
        &[
            "moonshotai/Kimi-K3",
            "deepseek-ai/DeepSeek-V4-Pro-0813",
            "zai-org/GLM-5.3-Flash",
            "openai/gpt-oss-120b",
        ],
    ),
    ("typesafe", &["jev-latest", "jev-preview"]),
    ("upstage", &["solar-pro-4", "solar-mini-4"]),
    (
        "venice",
        &[
            "claude-opus-5-5",
            "openai-gpt-6-sol",
            "deepseek-v4-1-flash",
            "z-ai-glm-5-3-flash",
        ],
    ),
    (
        "vercel",
        &[
            "anthropic/claude-opus-5",
            "openai/gpt-6-astra",
            "google/gemini-3.5-flash-lite",
            "openai/gpt-5-nano",
        ],
    ),
    (
        "volcengine",
        &[
            "doubao-seed-2-1-pro-260915",
            "doubao-seed-2-1-lite-260915",
            "deepseek-v4-pro-ga-260813",
            "deepseek-v4-1-flash-261017",
        ],
    ),
    (
        "vultr",
        &[
            "glm-5.3",
            "deepseek-v4.1-flash-1017",
            "glm-5.3-flash",
            "qwen3.8-27b",
        ],
    ),
    (
        "wandb",
        &[
            "deepseek-ai/DeepSeek-V4-Pro-0813",
            "zai-org/GLM-5.3",
            "zai-org/GLM-5.3-Flash",
            "openai/gpt-oss-20b",
        ],
    ),
    (
        "watsonx",
        &[
            "openai/gpt-oss-120b",
            "meta-llama/llama-3-3-70b-instruct",
            "ibm/granite-4-h-small",
            "mistralai/mistral-small-3-1-24b-instruct-2503",
        ],
    ),
    (
        "xai",
        &["grok-4.7", "grok-4.3", "grok-4.20-0309-non-reasoning"],
    ),
    ("zai", &["glm-5.3", "glm-5.2", "glm-5.3-flash"]),
    ("zai-coding", &["glm-5.4", "glm-5.3"]),
    (
        "zenmux",
        &[
            "anthropic/claude-opus-5",
            "openai/gpt-5.4-mini",
            "deepseek/deepseek-v4-pro",
            "z-ai/glm-5.3-flash",
        ],
    ),
    (
        "zhipu",
        &["glm-5.3", "glm-5.1", "glm-4.7-flash", "glm-4.5-air"],
    ),
];

/// The models a catalog provider starts with: the starter set, else [`DEFAULT_MODELS`], else none.
pub fn default_models(id: &str) -> &'static [&'static str] {
    START_PROVIDERS
        .iter()
        .chain(DEFAULT_MODELS)
        .find(|(known, _)| *known == id)
        .map_or(&[], |(_, models)| models)
}

/// The policy lines of provider `id` (one of [`START_PROVIDERS`]) as `enterplace start` and Connect a model write it,
/// with its key given by `key_line` (`key_env: OPENAI_PROVIDER_KEY` or `credential: openai`). Its URL comes from
/// `ENTERPLACE_<ID>_BASE_URL` when `env` has it: a proxy in front of the provider, or a mock in a test.
pub fn start_provider(
    id: &str,
    key_line: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let (id, models) = START_PROVIDERS.iter().find(|(known, _)| *known == id)?;
    let mut lines = format!(
        "  - name: {id}\n    preset: {id}\n    {key_line}\n    models: [{}]\n",
        models.join(", ")
    );
    if let Some(url) = env(&base_url_env(id)).filter(|u| !u.trim().is_empty()) {
        let url = url.trim();
        lines.push_str(&format!("    url: {url}\n"));
        if crate::config::is_private(url) {
            lines.push_str("    allow_private: true\n");
        }
    }
    Some(lines)
}

/// The name of the provider that sends Claude Code's own subscription logins on (`auth: passthrough`).
pub const SUBSCRIPTION_PROVIDER: &str = "claude-subscriptions";

/// The policy lines of the passthrough provider `enterplace start` and the console's Coding agents step write: Claude
/// Code on the developers' own Claude subscriptions, with no Anthropic key at all. `identity: required` refuses a
/// request that names no person: every call carries a name, and `enterplace start` hands the first person a token.
/// Its URL comes from `ENTERPLACE_ANTHROPIC_BASE_URL` as the keyed provider's does.
pub fn subscription_provider(env: &dyn Fn(&str) -> Option<String>) -> String {
    let mut lines = format!(
        "  # Claude Code on your developers' own Claude subscriptions (Pro, Max, Team, Enterprise): each request carries\n  # the person's own Claude login, sent on unchanged and never kept. Enterplace holds no Anthropic key for it.\n  - name: {SUBSCRIPTION_PROVIDER}\n    kind: anthropic\n    auth: passthrough\n    # Each request names its person with a person token in x-enterplace-user. optional lets one without in, as the\n    # person unknown.\n    identity: required\n    models: [\"claude-*\"]\n"
    );
    match env(&base_url_env("anthropic")).filter(|u| !u.trim().is_empty()) {
        Some(url) => {
            let url = url.trim();
            lines.push_str(&format!("    url: {url}\n"));
            if crate::config::is_private(url) {
                lines.push_str("    allow_private: true\n");
            }
        }
        None => lines.push_str("    url: https://api.anthropic.com\n"),
    }
    lines
}

/// The variable that points a provider `enterplace start` sets up at another URL: `ENTERPLACE_OPENAI_BASE_URL`. Not
/// `OPENAI_BASE_URL`, which the console tells people to set to Enterplace itself in their shell.
pub fn base_url_env(id: &str) -> String {
    format!("ENTERPLACE_{}_BASE_URL", id.to_ascii_uppercase())
}

pub fn find(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id == id)
}

/// `enterplace providers`: one line per entry, aligned, for a terminal.
pub fn table() -> String {
    let width = PRESETS.iter().map(|p| p.id.len()).max().unwrap_or(0);
    let name_width = PRESETS.iter().map(|p| p.name.len()).max().unwrap_or(0);
    let mut out = format!(
        "{:width$}  {:name_width$}  {:9}  URL\n",
        "ID", "NAME", "KIND"
    );
    for p in PRESETS {
        let url = if p.local {
            format!("{} (local, needs allow_private: true)", p.url)
        } else {
            p.url.to_string()
        };
        out.push_str(&format!(
            "{:width$}  {:name_width$}  {:9}  {url}\n",
            p.id,
            p.name,
            p.kind.word()
        ));
    }
    out
}

/// The reference page in the docs. A test keeps the file in step with the table, so the page cannot drift.
pub fn page() -> String {
    let mut out = String::from(
        "---\n\
title: Provider catalog\n\
description: Every provider a policy can name with preset, with its URL, its kind and the documentation the URL came from.\n\
---\n\
\n\
{/* Generated from crates/enterplace-core/src/catalog.rs by `enterplace providers --markdown`. Do not edit by hand. */}\n\
\n\
A provider in the policy file may say `preset: <id>` instead of writing its `url` and `kind`. Enterplace takes both from this table; a `url` or `kind` written next to the preset wins. The provider still needs `key_env` (or `key_file`) and `models`.\n\
\n\
```yaml\n\
providers:\n\
  - name: groq\n\
    preset: groq\n\
    key_env: GROQ_API_KEY\n\
    models: [llama-3.3-70b-versatile]\n\
```\n\
\n\
The key goes in the header the kind sends: `Authorization: Bearer` for openai, `x-api-key` for anthropic, `x-goog-api-key` for gemini. A chat request goes to the URL followed by `/chat/completions` (anthropic: `/messages`; gemini: `/models/<model>:generateContent`).\n\
\n\
Local entries are model servers you run yourself. Their URL is the server's default on this machine, so the provider also needs `allow_private: true`, and `key_env` only if the server was started with a key. Run `enterplace providers` to print this table.\n\
\n\
| ID | Name | Kind | URL | Source |\n\
| --- | --- | --- | --- | --- |\n",
    );
    for p in PRESETS {
        let local = if p.local { " (local)" } else { "" };
        out.push_str(&format!(
            "| `{}` | {}{local} | {} | `{}` | [docs]({}) |\n",
            p.id,
            p.name,
            p.kind.word(),
            p.url,
            p.docs
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Loaded, load_texts};
    use std::path::Path;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn hosted_providers_start_with_models_a_policy_accepts() -> TestResult {
        assert!(default_models("groq").contains(&"llama-3.3-70b-versatile"));
        assert_eq!(default_models("openai"), START_PROVIDERS[0].1);
        assert!(default_models("ollama").is_empty());
        let mut seen = std::collections::HashSet::new();
        for (id, models) in DEFAULT_MODELS {
            let preset = find(id).ok_or(format!("{id} is not in the catalog"))?;
            assert!(
                !preset.local,
                "{id} runs locally: its models are whatever it loaded"
            );
            assert!(seen.insert(*id), "{id} is listed twice");
            assert!(!models.is_empty(), "{id}");
            // Each list is written into a provider's models, so the check must take it.
            let url = match (preset.needs_url(), *id) {
                (true, _) => "    url: https://x.example.com\n",
                (_, "watsonx") => "    project_id: 0f6c1c3e-5d6a-4b4e-9b1e-2a7d1c9f0a11\n",
                _ => "",
            };
            let provider = format!(
                "  - name: p\n    preset: {id}\n    key_env: K\n{url}    models: [{}]\n",
                models
                    .iter()
                    .map(|m| format!("\"{m}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            check(&provider).map_err(|e| format!("{id}: {}", e.join(" ")))?;
        }
        Ok(())
    }

    fn check(provider: &str) -> Result<Loaded, Vec<String>> {
        let policy = format!(
            "version: 1\nproviders:\n{provider}rules:\n  - name: everyone\n    principals: {{ any: true }}\n    models: [\"*\"]\n"
        );
        load_texts(
            Path::new("enterplace.policy.yaml"),
            &policy,
            Path::new("enterplace.keys.yaml"),
            "",
        )
    }

    #[test]
    fn a_preset_gives_the_url_and_the_kind() -> TestResult {
        let loaded = check(
            "  - name: groq\n    preset: groq\n    key_env: GROQ_API_KEY\n    models: [llama-3.3-70b-versatile]\n",
        )
        .map_err(|e| e.join("\n"))?;
        let groq = loaded.providers.first().ok_or("no provider")?;
        assert_eq!(groq.url, "https://api.groq.com/openai/v1");
        assert_eq!(groq.kind, Kind::OpenAi);
        Ok(())
    }

    #[test]
    fn a_preset_of_another_kind_gives_that_kind() -> TestResult {
        let loaded = check(
            "  - name: claude\n    preset: anthropic\n    key_env: ANTHROPIC_API_KEY\n    models: [claude-sonnet-5-5]\n",
        )
        .map_err(|e| e.join("\n"))?;
        let claude = loaded.providers.first().ok_or("no provider")?;
        assert_eq!(claude.kind, Kind::Anthropic);
        assert_eq!(claude.url, "https://api.anthropic.com/v1");
        Ok(())
    }

    #[test]
    fn fields_written_next_to_a_preset_win() -> TestResult {
        let loaded = check(
            "  - name: groq\n    preset: groq\n    url: https://groq.example.com/openai/v1\n    kind: openai\n    key_env: GROQ_API_KEY\n    models: [m]\n",
        )
        .map_err(|e| e.join("\n"))?;
        let groq = loaded.providers.first().ok_or("no provider")?;
        assert_eq!(groq.url, "https://groq.example.com/openai/v1");
        Ok(())
    }

    #[test]
    fn an_unknown_preset_fails_with_the_closest_id() -> TestResult {
        let Err(errors) =
            check("  - name: g\n    preset: grok\n    key_env: GROQ_API_KEY\n    models: [m]\n")
        else {
            return Err("an unknown preset was accepted".into());
        };
        let all = errors.join("\n");
        assert!(all.contains("enterplace.policy.yaml:4:"), "{all}");
        assert!(all.contains("\"grok\""), "{all}");
        assert!(all.contains("did you mean groq?"), "{all}");
        assert!(all.contains("enterplace providers"), "{all}");
        Ok(())
    }

    #[test]
    fn a_local_preset_needs_allow_private_and_no_key() -> TestResult {
        let Err(errors) = check("  - name: ollama\n    preset: ollama\n    models: [llama3]\n")
        else {
            return Err("a local preset was accepted without allow_private".into());
        };
        assert!(
            errors.join("\n").contains("allow_private: true"),
            "{errors:?}"
        );
        let loaded = check(
            "  - name: ollama\n    preset: ollama\n    allow_private: true\n    models: [llama3]\n",
        )
        .map_err(|e| e.join("\n"))?;
        let ollama = loaded.providers.first().ok_or("no provider")?;
        assert_eq!(ollama.url, "http://localhost:11434/v1");
        Ok(())
    }

    #[test]
    fn the_catalog_holds_100_providers_each_once_sorted_and_valid() -> TestResult {
        assert!(PRESETS.len() >= 100, "{} providers", PRESETS.len());
        for pair in PRESETS.windows(2) {
            assert!(
                pair[0].id < pair[1].id,
                "{} then {}: keep ids sorted and unique",
                pair[0].id,
                pair[1].id
            );
        }
        for p in PRESETS {
            let url = crate::config::base_url(p.url).map_err(|e| format!("{}: {e}", p.id))?;
            assert_eq!(url, p.url, "{}: no trailing slash", p.id);
            // A path, so join sends the route after /v1 and the entry's own path is kept.
            let path = url.split_once("://").map(|(_, rest)| rest.contains('/'));
            assert_eq!(
                path,
                Some(true),
                "{}: the url needs the vendor's path",
                p.id
            );
            assert_eq!(
                p.local,
                url.starts_with("http://"),
                "{}: local means http on this machine",
                p.id
            );
            assert!(p.docs.starts_with("https://"), "{}: docs", p.id);
            assert!(crate::config::valid_name(p.id), "{}: id", p.id);
        }
        Ok(())
    }

    #[test]
    fn the_docs_page_matches_the_catalog() -> TestResult {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/src/content/docs/reference/providers.mdx");
        // A Windows checkout may turn the page's line ends into CRLF: the text is what must match.
        let written = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        assert!(
            written == page(),
            "{} is out of date. Run `cargo run -p enterplace-cli -- providers --markdown > docs/src/content/docs/reference/providers.mdx`.",
            path.display()
        );
        Ok(())
    }
}
