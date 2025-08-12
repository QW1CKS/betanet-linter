"use strict";
// Formatting helpers for compliance report output
// Extracted for ISSUE-027 to eliminate repeated 'Missing:' list assembly logic.
Object.defineProperty(exports, "__esModule", { value: true });
exports.missingList = missingList;
// Join provided (string | false) parts into a comma separated list.
// Falsy entries are skipped. Returned string does not include any prefix so
// callers can embed it inside custom failure messages.
function missingList(parts) {
    return parts.filter(Boolean).join(', ');
}
//# sourceMappingURL=format.js.map