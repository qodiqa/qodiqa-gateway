package dev.qodiqa.sdk;

import java.util.Map;
import java.util.Set;

/** Every failure of a call: an HTTP error answer (status &gt; 0), a transport failure, or a local argument error. */
public class QodiqaException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  /** Classification shared with the JavaScript, Python and Go SDKs. */
  public enum Kind { AUTHENTICATION, AUTHORIZATION, VALIDATION, NOT_FOUND, RATE_LIMIT, SERVER, VERIFICATION, MFA_REQUIRED, MFA_ENROLLMENT, MFA_LOCKED, NETWORK, TIMEOUT, OTHER }

  private final Kind kind;
  private final int status;
  private final String reason;
  private final String requestId;
  private final transient Map<String, Object> details;
  private final int retryAfterSeconds;

  public QodiqaException(Kind kind, int status, String reason, String message, String requestId, Map<String, Object> details, int retryAfterSeconds, Throwable cause) {
    super(message, cause);
    this.kind = kind;
    this.status = status;
    this.reason = reason;
    this.requestId = requestId;
    this.details = details == null ? Map.of() : details;
    this.retryAfterSeconds = retryAfterSeconds;
  }

  static QodiqaException validation(String message) {
    return new QodiqaException(Kind.VALIDATION, 0, "INVALID_ARGUMENT", message, null, null, 0, null);
  }

  public Kind kind() { return kind; }
  /** HTTP status, 0 when there was no answer. */
  public int status() { return status; }
  public String reason() { return reason; }
  public String requestId() { return requestId; }
  public Map<String, Object> details() { return details; }
  /** Seconds the server asked to wait, 0 when it did not. */
  public int retryAfterSeconds() { return retryAfterSeconds; }

  private static final Set<String> VERIFICATION_REASONS = Set.of("INVALID_ARTIFACT", "INVALID_SIGNATURE", "FUTURE_TIMESTAMP", "EXPIRED", "TIME_SKEW_EXCEEDED", "KEY_REVOKED",
      "KEY_ARCHIVED", "KEY_DEPRECATED", "KEY_NOT_YET_ACTIVE", "KEY_STATUS_UNKNOWN", "REQUEST_MISMATCH", "REPLAY_DETECTED");

  static Kind classify(int status, String reason) {
    if ("MFA_REQUIRED".equals(reason) || "MFA_INVALID".equals(reason)) return Kind.MFA_REQUIRED;
    if ("MFA_ENROLLMENT_REQUIRED".equals(reason)) return Kind.MFA_ENROLLMENT;
    if ("MFA_LOCKED".equals(reason)) return Kind.MFA_LOCKED;
    if (status == 401 || "UNAUTHORIZED".equals(reason) || "UNAUTHENTICATED".equals(reason)) return Kind.AUTHENTICATION;
    if (VERIFICATION_REASONS.contains(reason)) return Kind.VERIFICATION;
    if (status == 403 || "FORBIDDEN".equals(reason)) return Kind.AUTHORIZATION;
    if (status == 404 || "NOT_FOUND".equals(reason)) return Kind.NOT_FOUND;
    if (status == 429) return Kind.RATE_LIMIT;
    if (status == 400 || status == 422) return Kind.VALIDATION;
    if (status >= 500) return Kind.SERVER;
    return Kind.OTHER;
  }

  @Override
  public String getMessage() {
    StringBuilder sb = new StringBuilder(super.getMessage());
    if (status > 0) sb.append(" (HTTP ").append(status).append(reason != null && !"UNKNOWN".equals(reason) ? ", " + reason : "").append(')');
    if (requestId != null && !requestId.isEmpty()) sb.append(" [request ").append(requestId).append(']');
    return sb.toString();
  }
}
