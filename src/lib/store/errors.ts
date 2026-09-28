/**
 * Store error types. Kept in their own module so both the facade and every
 * backend implementation (memory, supabase) throw the exact same classes and
 * the API layer's `instanceof` checks keep working regardless of backend.
 */

export class NotAuthorizedError extends Error {
  constructor() {
    super("Not authorized to access this resource");
    this.name = "NotAuthorizedError";
  }
}

export class NotFoundError extends Error {
  constructor() {
    super("Resource not found");
    this.name = "NotFoundError";
  }
}

export class EmailInUseError extends Error {
  constructor() {
    super("An account with this email already exists");
    this.name = "EmailInUseError";
  }
}

/** Verification could not produce conclusive evidence, so it must not resolve. */
export class VerificationUnavailableError extends Error {
  constructor() {
    super("Verification could not produce conclusive evidence");
    this.name = "VerificationUnavailableError";
  }
}

/** No valid login session. Saved projects and their data require a real user. */
export class UnauthenticatedError extends Error {
  constructor() {
    super("Login required");
    this.name = "UnauthenticatedError";
  }
}

/**
 * An expected, user-explainable failure with an HTTP status and a stable code.
 * `userMessage` is shown to the user as-is, so it must never contain source
 * code, secrets, or internal details.
 */
export class AppError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly userMessage: string,
    readonly extra?: Record<string, unknown>
  ) {
    super(`${code}: ${userMessage}`);
    this.name = "AppError";
  }
}

/**
 * The database is missing a table/column this code needs. We fail loudly
 * instead of silently dropping data (the old "retry without the new columns"
 * fallback made unsaved data look saved).
 */
export class SchemaMigrationRequiredError extends AppError {
  constructor(what: string) {
    super(
      503,
      "schema_migration_required",
      "저장소 설정을 마무리하지 못해 지금은 저장할 수 없어요. 관리자에게 알려 주세요.",
      { what }
    );
    this.name = "SchemaMigrationRequiredError";
  }
}
