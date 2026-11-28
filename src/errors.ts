export class CogniWeaveError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class ValidationError extends CogniWeaveError {}

export class ScopeViolationError extends CogniWeaveError {}

export class IdempotencyConflictError extends CogniWeaveError {}

export class StorageConsistencyError extends CogniWeaveError {}

export class DistillationError extends CogniWeaveError {}

export class ReasoningError extends CogniWeaveError {}

export class EvidenceAccessError extends CogniWeaveError {}

export class StoreUnavailableError extends CogniWeaveError {}

export type ExecutionAuthorizationErrorCode =
  | "principal_unavailable"
  | "delegation_denied"
  | "delegation_store_unavailable"
  | "binding_store_unavailable"
  | "unauthorized"
  | "untrusted_runtime"
  | "security_override_rejected";

/**
 * Fail-closed authorization failure. `decision` carries the CW-09-02 audit trace.
 * The decision type is structurally compatible with ExecutionAuthorizationDecision.
 */
export class ExecutionAuthorizationError<TDecision = unknown> extends CogniWeaveError {
  readonly code: ExecutionAuthorizationErrorCode;
  readonly decision: TDecision;

  constructor(code: ExecutionAuthorizationErrorCode, message: string, decision: TDecision) {
    super(message);
    this.code = code;
    this.decision = decision;
  }
}

export class PrincipalUnavailableError<TDecision = unknown> extends ExecutionAuthorizationError<TDecision> {
  constructor(message: string, decision: TDecision) {
    super("principal_unavailable", message, decision);
  }
}

export class DelegationDeniedError<TDecision = unknown> extends ExecutionAuthorizationError<TDecision> {
  constructor(message: string, decision: TDecision) {
    super("delegation_denied", message, decision);
  }
}

export class DelegationStoreUnavailableError<TDecision = unknown> extends ExecutionAuthorizationError<TDecision> {
  constructor(message: string, decision: TDecision) {
    super("delegation_store_unavailable", message, decision);
  }
}

export class BindingStoreUnavailableError<TDecision = unknown> extends ExecutionAuthorizationError<TDecision> {
  constructor(message: string, decision: TDecision) {
    super("binding_store_unavailable", message, decision);
  }
}

export class UntrustedRuntimeError<TDecision = unknown> extends ExecutionAuthorizationError<TDecision> {
  constructor(message: string, decision: TDecision) {
    super("untrusted_runtime", message, decision);
  }
}

export class SecurityOverrideRejectedError<TDecision = unknown> extends ExecutionAuthorizationError<TDecision> {
  constructor(message: string, decision: TDecision) {
    super("security_override_rejected", message, decision);
  }
}

export type ProductionBootstrapFailureReason =
  | "process_not_production"
  | "mixed_test_and_production_configuration"
  | "missing_bootstrap_authority"
  | "invalid_engine_environment"
  | "caller_injection_rejected"
  | "required_service_missing"
  | "untrusted_service_implementation"
  | "canonical_store_binding_query_mismatch"
  | "assembly_already_sealed"
  | "public_api_not_production_authority"
  | "engine_construction_rejected"
  | "untrusted_store_replacement"
  | "production_factory_denied";

/**
 * Fail-closed production bootstrap failure. The attached audit record is not a
 * runtime capability and cannot be submitted to prove assembly trust.
 */
export class ProductionBootstrapError extends CogniWeaveError {
  readonly reason: ProductionBootstrapFailureReason;
  readonly audit: Readonly<Record<string, unknown>>;

  constructor(
    message: string,
    reason: ProductionBootstrapFailureReason,
    audit: Readonly<Record<string, unknown>>,
  ) {
    super(message);
    this.reason = reason;
    this.audit = audit;
  }
}
