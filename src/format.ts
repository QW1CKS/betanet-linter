// Formatting helpers for compliance report output
// Extracted for ISSUE-027 to eliminate repeated 'Missing:' list assembly logic.

// Join provided (string | false) parts into a comma separated list.
// Falsy entries are skipped. Returned string does not include any prefix so
// callers can embed it inside custom failure messages.
export function missingList(parts: Array<string | false>): string {
  return parts.filter(Boolean).join(', ');
}
