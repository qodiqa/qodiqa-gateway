"""Policy Simulation resource — Component #40.

Provides synchronous and asynchronous clients for:

* ``POST /v1/policy/simulate``       — single simulation
* ``POST /v1/policy/compare``        — policy comparison
* ``POST /v1/policy/simulate/batch`` — batch simulation

All operations are read-only.  ``executionPrevented: True`` is always present
in every response item returned by the server.

Example (sync)::

    from qodiqa import QodiqaClient

    with QodiqaClient(base_url="http://localhost:3000", api_key="ok_...") as client:
        result = client.simulation.simulate({
            "context": {
                "userId": "my-key:key_v1",
                "action": "openai",
                "ip": "192.168.1.1",
            }
        })
        print(result["data"]["decision"])   # "EXECUTE" or "BLOCK"

Example (async)::

    from qodiqa import AsyncQodiqaClient

    async with AsyncQodiqaClient(base_url="...", api_key="ok_...") as client:
        result = await client.simulation.simulate({...})
"""

from __future__ import annotations

from typing import Any, cast, Dict, List, Optional

from ._base import AsyncBaseResource, BaseResource


SimulationRequest = Dict[str, Any]
SimulationResult  = Dict[str, Any]
CompareRequest    = Dict[str, Any]
CompareResult     = Dict[str, Any]
BatchRequest      = Dict[str, Any]
BatchResult       = Dict[str, Any]


class SimulationResource(BaseResource):
    """Policy simulation resource (synchronous).

    All methods require ops-level authentication.
    No production state is mutated by any call.
    """

    def simulate(self, request: SimulationRequest) -> SimulationResult:
        """Run a single policy simulation.

        The simulation evaluates the provided context against the live (or
        provided draft) policy set.  No nonce is registered, no anomaly
        counter is incremented, and no audit record is written.

        Args:
            request: Dict with optional keys:

                * ``context``  — dict with ``userId``, ``action``, ``tenantId``,
                  ``requestId``, ``ip``, ``timestamp``
                * ``policies`` — list of policy definitions (draft/proposed);
                  omit to use the live policy set
                * ``scenario`` — human-readable label

        Returns:
            API envelope dict.  ``data`` contains a :class:`SimulationResult`-
            shaped dict with ``decision``, ``reason``, ``evaluationTrace``,
            ``matchedRules``, ``failedRules``, ``riskLevel``, ``explanation``,
            and ``executionPrevented: True``.
        """
        headers = self._auth.get_auth_header()
        return cast('SimulationResult', self._http.post("/v1/policy/simulate", request, headers=headers))

    def compare(self, request: CompareRequest) -> CompareResult:
        """Compare two policy sets against the same context.

        Args:
            request: Dict with keys:

                * ``context``           — simulation context (optional)
                * ``currentPolicies``   — list of policies for the baseline;
                  omit to use the live policy set
                * ``proposedPolicies``  — list of policies for the proposed
                  version (required)
                * ``scenario``          — human-readable label (optional)

        Returns:
            API envelope dict.  ``data`` contains ``old``, ``proposed``,
            ``decisionChanged``, ``changedRules``, and
            ``executionPrevented: True``.
        """
        headers = self._auth.get_auth_header()
        return cast('CompareResult', self._http.post("/v1/policy/compare", request, headers=headers))

    def batch(self, request: BatchRequest) -> BatchResult:
        """Run up to 100 simulations concurrently.

        Args:
            request: Dict with keys:

                * ``simulations`` — list of dicts, each with ``context``,
                  optional ``policies``, and optional ``scenario``
                * ``policies``    — shared policy set applied when a simulation
                  item omits its own ``policies`` key (optional)

        Returns:
            API envelope dict.  ``data`` contains ``batchId``, ``total``,
            ``allowed``, ``blocked``, ``results``, and
            ``executionPrevented: True``.
        """
        headers = self._auth.get_auth_header()
        return cast('BatchResult', self._http.post("/v1/policy/simulate/batch", request, headers=headers))


class AsyncSimulationResource(AsyncBaseResource):
    """Policy simulation resource (asynchronous).

    All methods are identical to :class:`SimulationResource` but return
    awaitables.
    """

    async def simulate(self, request: SimulationRequest) -> SimulationResult:
        """Async version of :meth:`SimulationResource.simulate`."""
        headers = self._auth.get_auth_header()
        return cast('SimulationResult', await self._http.post("/v1/policy/simulate", request, headers=headers))

    async def compare(self, request: CompareRequest) -> CompareResult:
        """Async version of :meth:`SimulationResource.compare`."""
        headers = self._auth.get_auth_header()
        return cast('CompareResult', await self._http.post("/v1/policy/compare", request, headers=headers))

    async def batch(self, request: BatchRequest) -> BatchResult:
        """Async version of :meth:`SimulationResource.batch`."""
        headers = self._auth.get_auth_header()
        return cast('BatchResult', await self._http.post("/v1/policy/simulate/batch", request, headers=headers))
