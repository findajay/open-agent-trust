"""Deterministic action policies.

A policy is a list of rules that match action and resource name patterns. When several
rules match, ``deny`` beats ``require_approval`` beats ``allow``; when none match, the
policy's ``default`` applies. Evaluation is pure, so a verifier holding the same policy
reproduces the gateway's decision exactly (the policy digest pins which policy that was).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .canonical import digest
from .delegation import pattern_matches
from .models import Effect, Identifier, KeyId, NamePattern, PolicyDecision

_PRECEDENCE: dict[str, int] = {"deny": 0, "require_approval": 1, "allow": 2}


class PolicyError(ValueError):
    """A policy document is invalid."""


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: Identifier
    effect: Effect
    actions: Annotated[list[NamePattern], Field(min_length=1)]
    resources: Annotated[list[NamePattern], Field(min_length=1)] = ["*"]
    approvers: list[KeyId] = []
    description: str | None = None

    @model_validator(mode="after")
    def _approvers(self) -> Rule:
        if self.effect == "require_approval" and not self.approvers:
            raise ValueError(f"rule {self.id!r}: require_approval needs at least one approver")
        if self.effect != "require_approval" and self.approvers:
            raise ValueError(f"rule {self.id!r}: approvers only apply to require_approval")
        return self

    def matches(self, action: str, resource: str) -> bool:
        return any(pattern_matches(p, action) for p in self.actions) and any(
            pattern_matches(p, resource) for p in self.resources
        )


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: Identifier
    description: str | None = None
    default: Effect = "deny"
    rules: list[Rule]

    @model_validator(mode="after")
    def _unique_ids(self) -> PolicyDocument:
        ids = [rule.id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")
        if self.default == "require_approval":
            raise ValueError("default must be allow or deny (approval needs a rule's approvers)")
        return self


@dataclass(frozen=True)
class Policy:
    document: PolicyDocument
    digest: str

    @classmethod
    def from_mapping(cls, data: Any) -> Policy:
        try:
            document = PolicyDocument.model_validate(data)
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(part) for part in first["loc"]) or "$"
            raise PolicyError(f"{where}: {first['msg']}") from exc
        # The digest covers the normalised policy, so YAML formatting and defaulted
        # members do not change it, but any semantic change does.
        return cls(document, digest(document.model_dump(mode="json")))

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        path = Path(path)
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise PolicyError(f"{path}: not valid YAML: {exc}") from exc
        return cls.from_mapping(data)

    def evaluate(self, action: str, resource: str) -> PolicyDecision:
        matching = [rule for rule in self.document.rules if rule.matches(action, resource)]
        if not matching:
            default: Literal["allow", "deny"] = (
                "allow" if self.document.default == "allow" else "deny"
            )
            return PolicyDecision(
                effect=default,
                policy_id=self.document.id,
                policy_digest=self.digest,
                rule_id=None,
                approvers=[],
                reason=f"no rule matched; policy default is {default}",
            )
        # Stable: among equally strong rules, the first one in the document wins.
        rule = min(matching, key=lambda r: _PRECEDENCE[r.effect])
        return PolicyDecision(
            effect=rule.effect,
            policy_id=self.document.id,
            policy_digest=self.digest,
            rule_id=rule.id,
            approvers=list(rule.approvers),
            reason=(rule.description or f"matched rule {rule.id}")[:1024],
        )
