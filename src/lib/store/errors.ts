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
