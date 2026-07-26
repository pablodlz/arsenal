/**
 * Caido plugin — flags GraphQL mutations whose response cannot be used as an
 * authorisation oracle.
 *
 * The detection logic lives in ./detect.js so it can be unit-tested without
 * Caido (`npm test`, 17 cases pinned against real graphql-authz-lab responses).
 * This file is only the binding.
 *
 * Caido's plugin SDK surface has moved between releases. If `init` does not fire
 * on your version, check the current backend/frontend plugin contract in the
 * Caido docs and adjust the registration call below — `classify()` itself needs
 * no changes.
 */

import { classify } from "./detect.js";

const NAME = "phantom-success";

/** Read a body off whatever shape the SDK hands us. */
function bodyOf(part) {
  if (!part) return "";
  try {
    const raw = typeof part.getBody === "function" ? part.getBody() : part.body;
    if (!raw) return "";
    if (typeof raw === "string") return raw;
    if (typeof raw.toText === "function") return raw.toText();
    if (typeof raw.toString === "function") return raw.toString();
    return "";
  } catch {
    return "";
  }
}

function pathOf(request) {
  if (!request) return "";
  try {
    if (typeof request.getPath === "function") return request.getPath();
    return request.path ?? "";
  } catch {
    return "";
  }
}

/**
 * Inspect one exchange and return a finding, or null.
 * Exported so it can be driven from tests or another host.
 */
export function inspect(request, response) {
  const result = classify({
    path: pathOf(request),
    requestBody: bodyOf(request),
    responseBody: bodyOf(response),
  });
  return result.flagged ? result : null;
}

export function init(sdk) {
  const log = sdk?.console ?? console;

  const handler = (request, response) => {
    const finding = inspect(request, response);
    if (!finding) return;

    const title = `Phantom success: ${finding.mutation}`;

    // Prefer the findings API when the host exposes it; fall back to logging so
    // the plugin is still useful on a version whose API differs.
    if (typeof sdk?.findings?.create === "function") {
      sdk.findings.create({
        title,
        description: finding.reason,
        severity: finding.severity,
        reporter: NAME,
        request,
      });
    } else {
      log.log(`[${NAME}] ${title} — ${finding.reason}`);
    }
  };

  if (typeof sdk?.events?.onInterceptResponse === "function") {
    sdk.events.onInterceptResponse(handler);
  } else if (typeof sdk?.http?.onResponse === "function") {
    sdk.http.onResponse(handler);
  } else {
    log.log(`[${NAME}] no response hook found on this SDK version; plugin idle.`);
  }

  log.log(`[${NAME}] loaded`);
}

export default { init, inspect };
