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
    /// The header the provider key goes in. It follows from the kind: Gantry sends it as `config::Kind` says.
    pub fn key_header(&self) -> &'static str {
        match self.kind {
            Kind::Anthropic => "x-api-key",
            Kind::Gemini => "x-goog-api-key",
            Kind::Azure => "api-key",
            Kind::OpenAi | Kind::Vertex | Kind::VertexAnthropic | Kind::Bedrock => {
                "Authorization: Bearer"
            }
        }
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
        "deepinfra",
        "DeepInfra",
        "https://api.deepinfra.com/v1/openai",
        "https://docs.deepinfra.com/chat/overview",
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
    hosted(
        "requesty",
        "Requesty",
        "https://router.requesty.ai/v1",
        "https://docs.requesty.ai/quickstart",
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
pub fn find(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id == id)
}

/// `gantry providers`: one line per entry, aligned, for a terminal.
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
{/* Generated from crates/gantry-core/src/catalog.rs by `gantry providers --markdown`. Do not edit by hand. */}\n\
\n\
A provider in the policy file may say `preset: <id>` instead of writing its `url` and `kind`. Gantry takes both from this table; a `url` or `kind` written next to the preset wins. The provider still needs `key_env` (or `key_file`) and `models`.\n\
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
Local entries are model servers you run yourself. Their URL is the server's default on this machine, so the provider also needs `allow_private: true`, and `key_env` only if the server was started with a key. Run `gantry providers` to print this table.\n\
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

    fn check(provider: &str) -> Result<Loaded, Vec<String>> {
        let policy = format!(
            "version: 1\nproviders:\n{provider}rules:\n  - name: everyone\n    principals: {{ any: true }}\n    models: [\"*\"]\n"
        );
        load_texts(
            Path::new("gantry.policy.yaml"),
            &policy,
            Path::new("gantry.keys.yaml"),
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
        assert!(all.contains("gantry.policy.yaml:4:"), "{all}");
        assert!(all.contains("\"grok\""), "{all}");
        assert!(all.contains("did you mean groq?"), "{all}");
        assert!(all.contains("gantry providers"), "{all}");
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
            "{} is out of date. Run `cargo run -p gantry-cli -- providers --markdown > docs/src/content/docs/reference/providers.mdx`.",
            path.display()
        );
        Ok(())
    }
}
