from dataclasses import asdict, dataclass, field
from typing import Any, Literal


ScopeVisibility = Literal["private", "shared"]
AtomStatus = Literal["active", "tentative", "conflicted", "deprecated"]
AtomClaimType = Literal["causal", "procedural", "heuristic", "policy", "preference"]


@dataclass(slots=True)
class Scope:
    workspace_id: str
    project_id: str
    agent_id: str
    visibility: ScopeVisibility = "private"

    def to_payload(self) -> dict[str, str]:
        return {
            "workspaceId": self.workspace_id,
            "projectId": self.project_id,
            "agentId": self.agent_id,
            "visibility": self.visibility,
        }

    def to_headers(self) -> dict[str, str]:
        return {
            "x-cogniweave-workspace-id": self.workspace_id,
            "x-cogniweave-project-id": self.project_id,
            "x-cogniweave-agent-id": self.agent_id,
            "x-cogniweave-visibility": self.visibility,
        }


@dataclass(slots=True)
class TaskFrame:
    id: str
    scope: Scope
    task_type: str
    goals: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    scenario_tags: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)
    required_atom_types: list[str] = field(default_factory=list)
    risk_level: str | None = None
    priority: str | None = None


@dataclass(slots=True)
class MemoryAtom:
    id: str
    atom_type: str
    scope: Scope
    claim_type: AtomClaimType
    statement: str
    status: AtomStatus = "active"
    confidence: float = 0.8
    reuse_count: int = 0
    evidence_refs: list[str] = field(default_factory=list)
    dedup_key: str | None = None


@dataclass(slots=True)
class CognitivePackage:
    package_id: str
    task_frame_id: str
    answer_summary: str
    why_summary: str
    supporting_atoms: list[str] = field(default_factory=list)
    confidence: float = 0.0
    constraints: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MemoryResourceDescriptor:
    resource_id: str
    resource_type: str
    tenant_id: str
    owner_type: str
    owner_id: str
    scope: Scope
    visibility: ScopeVisibility
    privacy_level: str
    lifecycle_status: str
    version: int
    updated_at: str


def to_json_dict(value: object) -> object:
    if isinstance(value, Scope):
        return value.to_payload()
    if hasattr(value, "__dataclass_fields__"):
        return {k: to_json_dict(v) for k, v in asdict(value).items()}  # type: ignore[arg-type]
    if isinstance(value, list):
        return [to_json_dict(item) for item in value]
    if isinstance(value, dict):
        return {key: to_json_dict(item) for key, item in value.items()}
    return value
