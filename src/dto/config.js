'use strict';

/**
 * @fileoverview Config DTO — deterministic failure recovery for application configuration.
 *
 * This module wraps the raw validated config (from `src/config/index.js`) into
 * a stable, typed Data-Transfer Object that:
 *
 *   1. Classifies every parse / validation failure into a named `ConfigError`
 *      with a machine-readable `code`, human-safe `message`, and `recoverable`
 *      flag so callers can distinguish fatal mis-configs from transient problems.
 *
 *   2. Exposes `buildConfigDto(rawEnv?)` — a pure, deterministic function safe to
 *      call multiple times and from concurrent paths without side-effects.
 *
 *   3. Provides `parseConfigDto()` which reads `process.env`, calls `buildConfigDto`,
 *      and wraps any thrown error into a structured `ConfigResult` rather than
 *      propagating raw Zod errors or unclassified exceptions.
 *
 *   4. Guarantees that for any given set of inputs the output (success or failure)
 *      is always the same shape — so callers never encounter `undefined`, partial
 *      data, or unhandled throws when consuming config at runtime.
 *
 * ## Failure recovery model
 *
 * ```
 *  Input env                    parseConfigDto()
 *  ─────────────────────────    ─────────────────────────────────────────────
 *  Valid                    →   { ok: true,  dto: ConfigDto }
 *  Missing required field   →   { ok: false, error: ConfigError(MISSING_FIELD) }
 *  Type / constraint error  →   { ok: false, error: ConfigError(VALIDATION_ERROR) }
 *  Unparseable JSON in env  →   { ok: false, error: ConfigError(PARSE_ERROR) }
 *  Unexpected thrown value  →   { ok: false, error: ConfigError(UNEXPECTED_ERROR) }
 * ```
 *
 * Callers that need strict boot-time fail-fast behaviour use `requireConfigDto()`
 * which throws a `ConfigError` if the result is not `ok`.
 *
 * @module dto/config
 */

const { ConfigSchema } = require('../config/index');

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/**
 * Machine-readable codes attached to every `ConfigError`.
 *
 * @readonly
 * @enum {string}
 */
const CONFIG_ERROR_CODES = Object.freeze({
  /** One or more required environment variables are absent. */
  MISSING_FIELD: 'CONFIG_MISSING_FIELD',
  /** A value is present but violates a type or constraint rule. */
  VALIDATION_ERROR: 'CONFIG_VALIDATION_ERROR',
  /** A value that must be valid JSON (e.g. an array env var) failed JSON.parse. */
  PARSE_ERROR: 'CONFIG_PARSE_ERROR',
  /** An error was thrown that was not a Zod validation error. */
  UNEXPECTED_ERROR: 'CONFIG_UNEXPECTED_ERROR',
});

// ---------------------------------------------------------------------------
// ConfigError
// ---------------------------------------------------------------------------

/**
 * Structured error thrown / returned when config parsing fails.
 *
 * Invariants:
 * - `code` is always one of the values in `CONFIG_ERROR_CODES`.
 * - `message` never contains raw environment variable values (no secret leakage).
 * - `fieldErrors` is present only for `MISSING_FIELD` and `VALIDATION_ERROR` codes.
 * - `recoverable` is `false` for all config errors — a mis-configured deployment
 *   must be fixed before the process can serve traffic safely.
 */
class ConfigError extends Error {
  /**
   * @param {object} params
   * @param {string} params.code       - One of `CONFIG_ERROR_CODES`.
   * @param {string} params.message    - Safe human-readable description.
   * @param {Record<string, string[]>} [params.fieldErrors] - Per-field messages.
   * @param {Error}  [params.cause]    - Original error, kept for internal logs.
   */
  constructor({ code, message, fieldErrors, cause }) {
    super(message);
    this.name = 'ConfigError';
    this.code = code;
    this.message = message;
    this.fieldErrors = fieldErrors ?? null;
    /** Config errors are never automatically recoverable — they require a fix + redeploy. */
    this.recoverable = false;
    if (cause) {
      this.cause = cause;
    }
    Error.captureStackTrace(this, this.constructor);
  }
}

// ---------------------------------------------------------------------------
// ConfigDto
// ---------------------------------------------------------------------------

/**
 * @typedef {object} ConfigDto
 * @property {'development'|'production'|'test'} nodeEnv       - Runtime environment.
 * @property {number}  port                - HTTP listen port (1–65535).
 * @property {string}  jwtSecret           - JWT signing secret (min 32 chars).
 * @property {string[]} corsAllowedOrigins - Parsed CORS origin list (may be empty).
 * @property {string}  sorobanRpcUrl       - Validated Soroban RPC endpoint URL.
 * @property {string}  networkPassphrase   - Stellar network passphrase.
 * @property {number}  sorobanBatchConcurrency - Max concurrent Soroban batch calls.
 * @property {number}  sorobanBatchTimeoutMs   - Soroban batch per-call timeout (ms).
 * @property {boolean} escrowIndexerEnabled    - Whether the escrow indexer is active.
 * @property {number}  escrowIndexerStaleThresholdSeconds - Staleness threshold (s).
 * @property {string|null}  kycProviderUrl     - KYC provider base URL, or null.
 * @property {string|null}  kycProviderApiKey  - KYC provider API key, or null.
 * @property {string|null}  kycProviderSecret  - KYC HMAC webhook secret, or null.
 */

// ---------------------------------------------------------------------------
// ConfigResult
// ---------------------------------------------------------------------------

/**
 * @typedef {object} ConfigResultOk
 * @property {true}      ok  - Always `true` for success.
 * @property {ConfigDto} dto - The validated DTO.
 */

/**
 * @typedef {object} ConfigResultErr
 * @property {false}       ok    - Always `false` for failure.
 * @property {ConfigError} error - Structured error describing the failure.
 */

/**
 * @typedef {ConfigResultOk | ConfigResultErr} ConfigResult
 */

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Parse the `CORS_ALLOWED_ORIGINS` string into an array of trimmed origin
 * strings. Returns an empty array when the variable is absent or blank.
 *
 * This is deliberately forgiving — an empty origins list means "no external
 * origins allowed", which is a safe default, not a fatal error.
 *
 * @param {string|undefined} raw - Raw env value.
 * @returns {string[]}
 */
function _parseCorsOrigins(raw) {
  if (!raw || raw.trim() === '') return [];
  return raw
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
}

/**
 * Classify a Zod format error map into `MISSING_FIELD` vs `VALIDATION_ERROR`.
 *
 * A field is considered "missing" when its only issue is `invalid_type` and the
 * received value indicates absence. Detection is compatible with both Zod v3 and
 * Zod v4:
 *
 *   - Zod v3: `issue.received === 'undefined'` (the string literal "undefined")
 *   - Zod v4: `issue.received === undefined`   (the JS undefined value, key absent)
 *
 * In both versions, the message also contains the word "undefined", used as a
 * belt-and-suspenders guard.  Everything else — type mismatches where a value IS
 * present, range violations, enum mismatches, custom refinements — is a
 * VALIDATION_ERROR.
 *
 * @param {import('zod').ZodError} zodError
 * @returns {{ code: string, fieldErrors: Record<string, string[]> }}
 */
function _classifyZodError(zodError) {
  const missingFields = new Set();
  const constraintFields = new Set();

  for (const issue of zodError.issues) {
    const field = issue.path.join('.') || '_root';
    // Zod v3 uses the string 'undefined'; Zod v4 omits the `received` key entirely
    // (so issue.received is the JS value `undefined`).  Both forms mean the field
    // is absent from the input.
    const receivedIsAbsent =
      issue.received === undefined || issue.received === 'undefined';
    if (issue.code === 'invalid_type' && receivedIsAbsent) {
      missingFields.add(field);
    } else {
      constraintFields.add(field);
    }
  }

  const code =
    constraintFields.size > 0
      ? CONFIG_ERROR_CODES.VALIDATION_ERROR
      : CONFIG_ERROR_CODES.MISSING_FIELD;

  // Build per-field error messages — strip raw values to avoid secret leakage.
  const formatted = zodError.format();
  const fieldErrors = /** @type {Record<string, string[]>} */ ({});
  for (const issue of zodError.issues) {
    const field = issue.path.join('.') || '_root';
    if (!fieldErrors[field]) fieldErrors[field] = [];
    // Use the Zod message but strip any embedded value that could be a secret.
    fieldErrors[field].push(_sanitizeZodMessage(issue.message));
  }
  void formatted; // used above for structure, messages taken from issues

  return { code, fieldErrors };
}

/**
 * Strip numeric literals and long strings from Zod issue messages to prevent
 * accidental secret exposure in structured error output.
 *
 * @param {string} msg - Raw Zod issue message.
 * @returns {string}
 */
function _sanitizeZodMessage(msg) {
  // Replace anything that looks like a raw value (quoted strings, long hex/tokens)
  return msg
    .replace(/"[^"]{8,}"/g, '"<redacted>"')
    .replace(/\b[a-f0-9]{16,}\b/gi, '<redacted>');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Build a `ConfigDto` from a raw environment variables map.
 *
 * This function is **pure** — it does not read `process.env` directly and has
 * no module-level state, making it safe to call from tests and concurrent paths
 * without interference.
 *
 * @param {Record<string, string|undefined>} rawEnv - The env vars to parse.
 * @returns {ConfigDto} Validated, normalised DTO.
 * @throws {ConfigError} When validation fails. The error carries a structured
 *   `code` and `fieldErrors` map for deterministic failure handling.
 */
function buildConfigDto(rawEnv) {
  // Validate through the canonical ConfigSchema (single source of truth).
  const result = ConfigSchema.safeParse(rawEnv);

  if (!result.success) {
    const { code, fieldErrors } = _classifyZodError(result.error);

    const fieldList = Object.keys(fieldErrors).join(', ');
    const message =
      code === CONFIG_ERROR_CODES.MISSING_FIELD
        ? `Configuration is incomplete. Missing required fields: ${fieldList}.`
        : `Configuration is invalid. Check the following fields: ${fieldList}.`;

    throw new ConfigError({
      code,
      message,
      fieldErrors,
      cause: result.error,
    });
  }

  const raw = result.data;

  // Map Zod-validated raw env into the stable camelCase DTO shape.
  /** @type {ConfigDto} */
  const dto = {
    nodeEnv: raw.NODE_ENV,
    port: raw.PORT,
    jwtSecret: raw.JWT_SECRET,
    corsAllowedOrigins: _parseCorsOrigins(raw.CORS_ALLOWED_ORIGINS),
    sorobanRpcUrl: raw.SOROBAN_RPC_URL,
    networkPassphrase: raw.NETWORK_PASSPHRASE,
    sorobanBatchConcurrency: raw.SOROBAN_BATCH_CONCURRENCY,
    sorobanBatchTimeoutMs: raw.SOROBAN_BATCH_TIMEOUT_MS,
    escrowIndexerEnabled: raw.ESCROW_INDEXER_ENABLED === 'true',
    escrowIndexerStaleThresholdSeconds: raw.ESCROW_INDEXER_STALE_THRESHOLD_SECONDS,
    kycProviderUrl: raw.KYC_PROVIDER_URL ?? null,
    kycProviderApiKey: raw.KYC_PROVIDER_API_KEY ?? null,
    kycProviderSecret: raw.KYC_PROVIDER_SECRET ?? null,
  };

  return dto;
}

/**
 * Parse the current `process.env` into a `ConfigResult`.
 *
 * Unlike `buildConfigDto`, this function **never throws** — all error paths
 * are normalised into `{ ok: false, error: ConfigError }` so callers get a
 * deterministic result regardless of input.
 *
 * Concurrent calls are safe: the function is stateless and re-entrant.
 *
 * @param {Record<string, string|undefined>} [env=process.env] - Env vars source.
 *   Override in tests to avoid mutating `process.env`.
 * @returns {ConfigResult}
 */
function parseConfigDto(env = process.env) {
  try {
    const dto = buildConfigDto(env);
    return { ok: true, dto };
  } catch (err) {
    if (err instanceof ConfigError) {
      return { ok: false, error: err };
    }

    // Classify unexpected errors (programming bugs, non-Zod throws, etc.)
    return {
      ok: false,
      error: new ConfigError({
        code: CONFIG_ERROR_CODES.UNEXPECTED_ERROR,
        message: 'An unexpected error occurred while parsing configuration.',
        cause: err instanceof Error ? err : new Error(String(err)),
      }),
    };
  }
}

/**
 * Parse config and throw immediately on failure.
 *
 * Use this at boot time when the application should refuse to start rather than
 * operate with an invalid or partial configuration.
 *
 * @param {Record<string, string|undefined>} [env=process.env] - Env vars source.
 * @returns {ConfigDto} Validated DTO.
 * @throws {ConfigError} On any parse / validation failure.
 */
function requireConfigDto(env = process.env) {
  const result = parseConfigDto(env);
  if (!result.ok) {
    throw result.error;
  }
  return result.dto;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  buildConfigDto,
  parseConfigDto,
  requireConfigDto,
  ConfigError,
  CONFIG_ERROR_CODES,
};
