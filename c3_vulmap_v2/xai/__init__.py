"""XAI module for C3-VULMAP v2 LINDDUN labels.

    from xai import Explainer
    e = Explainer().explain("CWE-476", code)
    print(e.to_text())
"""

from .explain import Explainer, Explanation
from .chains import ChainIndex
from .overrides import OverrideTable

__all__ = ["Explainer", "Explanation", "ChainIndex", "OverrideTable"]
