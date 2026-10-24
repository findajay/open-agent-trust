"""OpenAgentTrust: verifiable authority for AI agent actions.

The public API, in the order an integration usually needs it::

    key = SigningKey.generate()                  # identities
    issue_delegation(org, agent.key_id, scope)   # authority
    Policy.load(path)                            # rules
    Gateway(...).execute(request, chain, tool)   # enforcement + receipt
    verify_receipt(receipt, ...)                 # independent verification
"""

from .delegation import DelegationError, issue_delegation
from .gateway import ExecutionResult, Gateway, RequestRejected
from .keys import PublicKey, SigningKey
from .ledger import Ledger
from .models import Scope
from .policy import Policy, PolicyError
from .requests import create_approval, create_request
from .verify import Report, verify_ledger, verify_receipt

__version__ = "0.1.0"

__all__ = [
    "DelegationError",
    "ExecutionResult",
    "Gateway",
    "Ledger",
    "Policy",
    "PolicyError",
    "PublicKey",
    "Report",
    "RequestRejected",
    "Scope",
    "SigningKey",
    "__version__",
    "create_approval",
    "create_request",
    "issue_delegation",
    "verify_ledger",
    "verify_receipt",
]
