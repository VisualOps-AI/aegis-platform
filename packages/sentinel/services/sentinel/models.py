import re
import uuid
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class FunctionDefinition(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=64)]
    description: str | None = None
    parameters: dict[str, Any] | None = None


class ToolFunction(BaseModel):
    type: Literal["function"] = "function"
    function: FunctionDefinition


class ContentPart(BaseModel):
    type: Literal["text", "image_url"]
    text: str | None = None
    image_url: dict[str, str] | None = None

    @model_validator(mode="after")
    def validate_content_part(self):
        if self.type == "text" and self.text is None:
            raise ValueError("text content part requires 'text' field")
        if self.type == "image_url" and self.image_url is None:
            raise ValueError("image_url content part requires 'image_url' field")
        return self


class Message(BaseModel):
    role: Literal["system", "user", "assistant", "tool", "function"]
    content: str | list[ContentPart] | None = None
    name: str | None = None
    tool_calls: list[dict[str, Any]] | None = None
    tool_call_id: str | None = None

    @field_validator("content", mode="before")
    @classmethod
    def validate_content_length(cls, v):
        if isinstance(v, str) and len(v) > 128000:
            raise ValueError("Message content exceeds maximum length (128000 chars)")
        return v


class ChatCompletionRequest(BaseModel):
    model: Annotated[str, Field(min_length=1, max_length=64)]
    messages: Annotated[list[Message], Field(min_length=1, max_length=256)]
    temperature: float | None = Field(default=None, ge=0, le=2)
    top_p: float | None = Field(default=None, ge=0, le=1)
    n: int | None = Field(default=None, ge=1, le=10)
    stream: bool | None = None
    stop: str | list[str] | None = None
    max_tokens: int | None = Field(default=None, ge=1, le=128000)
    presence_penalty: float | None = Field(default=None, ge=-2, le=2)
    frequency_penalty: float | None = Field(default=None, ge=-2, le=2)
    logit_bias: dict[str, float] | None = None
    user: str | None = None
    tools: list[ToolFunction] | None = None
    tool_choice: str | dict[str, Any] | None = None
    functions: list[FunctionDefinition] | None = None
    function_call: str | dict[str, str] | None = None
    response_format: dict[str, str] | None = None
    seed: int | None = None

    @model_validator(mode="after")
    def validate_messages_have_content(self):
        user_messages = [m for m in self.messages if m.role == "user"]
        if not user_messages:
            raise ValueError("At least one user message is required")
        return self


class RequestContext(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    validated_payload: ChatCompletionRequest | None = None

    @classmethod
    def create(cls, payload: dict[str, Any]) -> "RequestContext":
        validated = ChatCompletionRequest.model_validate(payload)
        return cls(validated_payload=validated)


def sanitize_for_logging(text: str, max_length: int = 50) -> str:
    if not text:
        return ""
    sanitized = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", text)
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    if len(sanitized) > max_length:
        return sanitized[:max_length] + "..."
    return sanitized


def get_payload_size(payload: dict[str, Any]) -> int:
    import json
    return len(json.dumps(payload))
