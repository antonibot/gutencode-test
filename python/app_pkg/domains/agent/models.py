"""API request/response models — typed seams, strict where input crosses the wire."""
from pydantic import BaseModel, StrictStr


class AgentIn(BaseModel):
    name: StrictStr
    system_prompt: StrictStr


class AgentOut(BaseModel):
    id: int
    name: str
    system_prompt: str


class SessionOut(BaseModel):
    id: int
    agent_id: int


class RunIn(BaseModel):
    input: StrictStr


class RunOut(BaseModel):
    session_id: int
    output: str
    iterations: int
    terminated: bool


class MessageOut(BaseModel):
    role: str
    content: str
