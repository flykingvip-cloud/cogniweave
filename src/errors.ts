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
  | "unauthorized";

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
