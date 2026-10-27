import { BaseResource } from './base.js';
import type {
  SimulationRequest,
  SimulationResult,
  PolicyComparisonRequest,
  PolicyComparisonResult,
  BatchSimulationRequest,
  BatchSimulationResult,
} from '../types.js';

export class SimulationResource extends BaseResource {
  /**
   * Run a single policy simulation against the live or provided policy set.
   *
   * Simulation is fully read-only: no nonce is registered, no anomaly counter
   * is incremented, no audit record is written, and no provider is contacted.
   * `executionPrevented: true` is always present in the response.
   *
   * `POST /v1/policy/simulate`
   *
   * @param request  Simulation request with context and optional policy set.
   */
  async simulate(request: SimulationRequest): Promise<SimulationResult> {
    const headers = this.auth.getAuthHeader();
    return this.http.post<SimulationResult>('/v1/policy/simulate', request, { headers });
  }

  /**
   * Compare two policy sets against the same context and return a structured
   * diff of which rules changed outcome.
   *
   * `POST /v1/policy/compare`
   *
   * @param request  Comparison request with context, current and proposed policies.
   */
  async compare(request: PolicyComparisonRequest): Promise<PolicyComparisonResult> {
    const headers = this.auth.getAuthHeader();
    return this.http.post<PolicyComparisonResult>('/v1/policy/compare', request, { headers });
  }

  /**
   * Evaluate up to 100 simulations concurrently.
   *
   * All simulations share the same fail-closed, read-only guarantees.
   * `executionPrevented: true` is present on every item in `results`.
   *
   * `POST /v1/policy/simulate/batch`
   *
   * @param request  Batch request with array of simulation items.
   */
  async batch(request: BatchSimulationRequest): Promise<BatchSimulationResult> {
    const headers = this.auth.getAuthHeader();
    return this.http.post<BatchSimulationResult>('/v1/policy/simulate/batch', request, { headers });
  }
}
