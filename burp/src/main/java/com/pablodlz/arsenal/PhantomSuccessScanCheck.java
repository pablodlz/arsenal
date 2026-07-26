package com.pablodlz.arsenal;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.List;
import java.util.regex.Pattern;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;

/**
 * Passive scan check: flags a GraphQL mutation whose response is a success
 * payload with an explicitly empty error slot and no rejection wording.
 *
 * <p>This is not an IDOR finding. It is the observation that the mutation
 * response carries no authorisation information, so it cannot be used to confirm
 * one. The reported issue tells you to re-send with an impossible object id and
 * compare — if the responses match, go measure state instead.
 *
 * <p>Background:
 * https://github.com/pablodlz/writeups/blob/main/web/graphql-phantom-success.md
 */
public class PhantomSuccessScanCheck implements BurpExtension, ScanCheck {

    private static final String NAME = "GraphQL mutation response is not an authorisation oracle";

    private static final Pattern MUTATION =
            Pattern.compile("mutation[^{]*\\{\\s*(\\w+)");

    private static final Pattern STATE_CHANGING = Pattern.compile(
            "^(delete|remove|update|set|create|add|transfer|revoke|disable|cancel|refund|archive|purge)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern EMPTY_ERROR_SLOT = Pattern.compile(
            "\"(error|errors|userErrors|problem)\"\\s*:\\s*(null|\\[\\s*\\])");

    private static final Pattern REJECTION = Pattern.compile(
            "not found|does not exist|no such|forbidden|unauthori[sz]ed|permission|denied"
                    + "|invalid id|cannot query field|unknown argument",
            Pattern.CASE_INSENSITIVE);

    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("arsenal — phantom success");
        api.scanner().registerScanCheck(this);
        api.logging().logToOutput("arsenal phantom-success check registered");
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse requestResponse) {
        if (requestResponse.request() == null || requestResponse.response() == null) {
            return auditResult(List.of());
        }

        String path = requestResponse.request().path();
        String requestBody = requestResponse.request().bodyToString();
        String responseBody = requestResponse.response().bodyToString();

        boolean looksGraphql = path.toLowerCase().contains("graphql")
                || path.toLowerCase().contains("/gql")
                || requestBody.contains("mutation");
        if (!looksGraphql) {
            return auditResult(List.of());
        }

        var m = MUTATION.matcher(requestBody);
        if (!m.find()) {
            return auditResult(List.of());
        }
        String mutation = m.group(1);

        // A response that rejects, anywhere, is a usable oracle. Nothing to say.
        if (REJECTION.matcher(responseBody).find()) {
            return auditResult(List.of());
        }
        if (!EMPTY_ERROR_SLOT.matcher(responseBody).find()) {
            return auditResult(List.of());
        }

        boolean stateChanging = STATE_CHANGING.matcher(mutation).find();

        String detail = "<p>The mutation <code>" + html(mutation) + "</code> returned a success "
                + "payload with an explicitly empty error slot, and the response contains no "
                + "rejection wording.</p>"
                + "<p><b>This is not, by itself, an authorisation flaw.</b> A resolver that "
                + "enforces ownership in its <code>WHERE</code> clause and never inspects the "
                + "affected row count produces exactly this response for a foreign id, an "
                + "impossible id, and a successful operation alike.</p>"
                + "<p><b>Next step:</b> re-send this request with a structurally impossible "
                + "object id — base64 of <code>Type:0</code> — and diff the responses. If they "
                + "match, the mutation response is not an authorisation oracle: confirm any "
                + "state change from an independent read in the victim's own session before "
                + "reporting an IDOR.</p>"
                + "<p>Tooling and write-up: "
                + "<a href=\"https://github.com/pablodlz/writeups/blob/main/web/graphql-phantom-success.md\">"
                + "graphql-phantom-success</a></p>";

        String remediation = "<p>Check the affected row count in the resolver and return an "
                + "explicit not-found or not-permitted error when it is zero, so the API stops "
                + "reporting success for operations that changed nothing.</p>";

        AuditIssue issue = AuditIssue.auditIssue(
                NAME,
                detail,
                remediation,
                requestResponse.request().url(),
                stateChanging ? AuditIssueSeverity.LOW : AuditIssueSeverity.INFORMATION,
                AuditIssueConfidence.FIRM,
                "GraphQL mutations that do not distinguish a no-op from a successful write "
                        + "make their own responses useless as an authorisation signal.",
                remediation,
                stateChanging ? AuditIssueSeverity.LOW : AuditIssueSeverity.INFORMATION,
                requestResponse);

        return auditResult(List.of(issue));
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse,
                                   AuditInsertionPoint auditInsertionPoint) {
        // Passive only, on purpose: the active version of this check would send a
        // mutation, and a scanner must not fire state-changing requests on its own.
        // Use scripts/phantom-probe.py when you want the differential run.
        return auditResult(List.of());
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return newIssue.detail().equals(existingIssue.detail()) ? KEEP_EXISTING : KEEP_BOTH;
    }

    private static String html(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
