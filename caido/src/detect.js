/**
 * Phantom-success detection, kept separate from the Caido bindings so it can be
 * unit-tested with plain node and reused by anything else.
 *
 * Background:
 * https://github.com/pablodlz/writeups/blob/main/web/graphql-phantom-success.md
 */

/** Wording a resolver uses when it genuinely rejects a request. */
const REJECTION =
  /not found|does not exist|no such|forbidden|unauthori[sz]ed|permission|denied|invalid id|cannot query field|unknown argument/i;

/** Mutation-ish operation names worth flagging (state-changing verbs). */
const STATE_CHANGING = /\b(delete|remove|update|set|create|add|transfer|revoke|disable|cancel|refund|archive|purge)\w*/i;

/**
 * Is this request body a GraphQL mutation? Returns the operation name, or null.
 * @param {string} requestBody
 * @returns {string|null}
 */
export function mutationName(requestBody) {
  if (!requestBody) return null;

  let query;
  try {
    const parsed = JSON.parse(requestBody);
    query = parsed?.query;
  } catch {
    query = requestBody;
  }
  if (typeof query !== "string" || !/\bmutation\b/.test(query)) return null;

  // first selected field inside the outermost brace
  const m = query.match(/mutation[^{]*\{\s*(\w+)/);
  return m ? m[1] : null;
}

/**
 * Does the response look like a success payload with an explicitly empty error
 * slot, and no rejection wording anywhere?
 * @param {string} responseBody
 * @returns {{empty: boolean, reason: string}}
 */
export function hasEmptyErrorSlot(responseBody) {
  if (!responseBody) return { empty: false, reason: "no body" };

  if (REJECTION.test(responseBody)) {
    return { empty: false, reason: "response contains rejection wording" };
  }

  let json;
  try {
    json = JSON.parse(responseBody);
  } catch {
    return { empty: false, reason: "body is not JSON" };
  }

  // top-level GraphQL errors present -> the API did tell us something
  if (Array.isArray(json.errors) && json.errors.length > 0) {
    return { empty: false, reason: "top-level errors present" };
  }
  if (!json.data || typeof json.data !== "object") {
    return { empty: false, reason: "no data object" };
  }

  // look for a payload field whose error slot is explicitly null
  for (const payload of Object.values(json.data)) {
    if (!payload || typeof payload !== "object") continue;
    for (const key of ["error", "errors", "userErrors", "problem"]) {
      if (key in payload) {
        const v = payload[key];
        const isEmpty = v === null || (Array.isArray(v) && v.length === 0);
        if (isEmpty) {
          return { empty: true, reason: `${key} is explicitly empty` };
        }
      }
    }
  }

  return { empty: false, reason: "no empty error slot found" };
}

/**
 * Classify one request/response pair.
 * @param {{requestBody?: string, responseBody?: string, path?: string}} exchange
 * @returns {{flagged: boolean, mutation: string|null, reason: string, severity: string}}
 */
export function classify(exchange) {
  const { requestBody = "", responseBody = "", path = "" } = exchange ?? {};

  const looksGraphql = /graphql|\/gql\b/i.test(path) || /\bmutation\b/.test(requestBody);
  if (!looksGraphql) {
    return { flagged: false, mutation: null, reason: "not a GraphQL exchange", severity: "info" };
  }

  const mutation = mutationName(requestBody);
  if (!mutation) {
    return { flagged: false, mutation: null, reason: "not a mutation", severity: "info" };
  }

  const slot = hasEmptyErrorSlot(responseBody);
  if (!slot.empty) {
    return { flagged: false, mutation, reason: slot.reason, severity: "info" };
  }

  // A state-changing verb with a silent error slot is the interesting case:
  // it is the shape that produces false-positive IDOR reports.
  const stateChanging = STATE_CHANGING.test(mutation);
  return {
    flagged: true,
    mutation,
    reason:
      `${mutation} returned a success payload with ${slot.reason}. ` +
      (stateChanging
        ? "Before treating this as proof of a state change, re-send with an impossible id " +
          "(base64 \"Type:0\") and compare. If the responses match, the mutation response " +
          "is not an authorisation oracle - confirm from an independent read instead."
        : "Not obviously state-changing; low signal."),
    severity: stateChanging ? "low" : "info",
  };
}
