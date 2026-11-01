"""Check that both providers convert the shared message history correctly. No API calls."""
from types import SimpleNamespace as NS

from patientzero.llm import ClaudeModel, OpenAIModel, ToolCall, ToolSpec

HISTORY = [
    {"role": "user", "content": "Email the summary"},
    {"role": "assistant", "content": None, "tool_calls": [ToolCall("c1", "read_email", {"email_id": "e1"}),
                                                          ToolCall("c2", "read_email", {"email_id": "e2"})]},
    {"role": "tool", "id": "c1", "name": "read_email", "content": "first"},
    {"role": "tool", "id": "c2", "name": "read_email", "content": "second"},
]
TOOLS = [ToolSpec("read_email", "Read one email", {"type": "object", "properties": {}})]


class FakeCreate:
    def __init__(self, response):
        self.response, self.kwargs = response, None

    def __call__(self, **kwargs):
        self.kwargs = kwargs
        return self.response


def test_claude_conversion_groups_tool_results_and_parses_tool_use():
    model = ClaudeModel.__new__(ClaudeModel)
    model.model, model.temperature, model.max_tokens = "claude-test", 0.0, 100
    create = FakeCreate(NS(content=[NS(type="text", text="Sending."),
                                    NS(type="tool_use", id="c3", name="send_email", input={"to": "a@acme.com"})],
                           usage=NS(input_tokens=10, output_tokens=5)))
    model.client = NS(messages=NS(create=create))
    reply = model.chat("system", HISTORY, TOOLS)
    sent = create.kwargs["messages"]
    assert [m["role"] for m in sent] == ["user", "assistant", "user"]
    assert [b["tool_use_id"] for b in sent[2]["content"]] == ["c1", "c2"]   # both results in one turn
    assert create.kwargs["tools"][0]["input_schema"] == TOOLS[0].schema
    assert reply.text == "Sending." and reply.tool_calls[0].args == {"to": "a@acme.com"}


def test_openai_conversion_and_reasoning_model_temperature():
    model = OpenAIModel.__new__(OpenAIModel)
    model.model, model.temperature = "gpt-5.4-mini", 0.0
    msg = NS(content=None, tool_calls=[NS(id="c3", function=NS(name="send_email", arguments='{"to": "a@acme.com"}'))])
    create = FakeCreate(NS(choices=[NS(message=msg)], usage=NS(prompt_tokens=10, completion_tokens=5)))
    model.client = NS(chat=NS(completions=NS(create=create)))
    reply = model.chat("system", HISTORY, TOOLS)
    sent = create.kwargs["messages"]
    assert sent[0] == {"role": "system", "content": "system"}
    assert sent[2]["tool_calls"][1]["function"]["name"] == "read_email"
    assert sent[3] == {"role": "tool", "tool_call_id": "c1", "content": "first"}
    assert "temperature" not in create.kwargs        # gpt-5 models only accept the default
    assert reply.tool_calls[0].name == "send_email"
