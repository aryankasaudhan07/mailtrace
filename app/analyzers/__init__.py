"""
Importing this package registers every analyzer. app/main.py imports it once
at startup; if you add a module, add it here or it silently never runs.
"""

from app.analyzers import (  # noqa: F401
    m2_headers,
    m3_auth,
    m4_content,
    m5_network,
    m6_domain,
    m7_graph,
)
from app.analyzers.base import registry, run_all  # noqa: F401
