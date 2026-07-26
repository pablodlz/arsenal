/**
 * node --test src/detect.test.js
 *
 * Fixtures are real response shapes captured from graphql-authz-lab in both
 * modes, so the tests pin the detector against behaviour that actually exists.
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import { classify, hasEmptyErrorSlot, mutationName } from "./detect.js";

const DELETE_REQ = JSON.stringify({
  query: 'mutation { deleteAddress(id: "QWRkcmVzczoyMDAx") { error { detail } } }',
});

// --- mutationName ---------------------------------------------------------

test("mutationName extracts the operation from a JSON body", () => {
  assert.equal(mutationName(DELETE_REQ), "deleteAddress");
});

test("mutationName handles a named operation", () => {
  const body = JSON.stringify({
    query: "mutation DeleteAddr($id: ID!) { deleteAddress(id: $id) { error { detail } } }",
  });
  assert.equal(mutationName(body), "deleteAddress");
});

test("mutationName accepts a raw (non-JSON) query body", () => {
  assert.equal(mutationName("mutation { setDefaultAddress(id: \"x\") { error } }"), "setDefaultAddress");
});

test("mutationName returns null for a query", () => {
  assert.equal(mutationName(JSON.stringify({ query: "{ addresses { id } }" })), null);
});

test("mutationName returns null for junk", () => {
  assert.equal(mutationName(""), null);
  assert.equal(mutationName("not json and not graphql"), null);
});

// --- hasEmptyErrorSlot ----------------------------------------------------

test("empty error slot detected on the vulnerable lab response", () => {
  const body = '{"data": {"deleteAddress": {"error": null}}}';
  assert.deepEqual(hasEmptyErrorSlot(body), {
    empty: true,
    reason: "error is explicitly empty",
  });
});

test("empty userErrors array detected (Shopify-style payload)", () => {
  const body = '{"data":{"customerUpdate":{"userErrors":[]}}}';
  assert.equal(hasEmptyErrorSlot(body).empty, true);
});

test("fixed lab response is NOT flagged", () => {
  const body = '{"data": {"deleteAddress": {"error": {"detail": "address not found"}}}}';
  assert.equal(hasEmptyErrorSlot(body).empty, false);
});

test("rejection wording anywhere suppresses the flag", () => {
  const body = '{"data":{"deleteAddress":{"error":null}},"note":"permission denied"}';
  assert.equal(hasEmptyErrorSlot(body).empty, false);
});

test("top-level GraphQL errors suppress the flag", () => {
  const body = '{"errors":[{"message":"Cannot query field \'adminDeleteAddress\'"}]}';
  assert.equal(hasEmptyErrorSlot(body).empty, false);
});

test("non-JSON body is not flagged", () => {
  assert.equal(hasEmptyErrorSlot("<html>500</html>").empty, false);
});

// --- classify -------------------------------------------------------------

test("classify flags the vulnerable lab exchange as low", () => {
  const r = classify({
    path: "/graphql",
    requestBody: DELETE_REQ,
    responseBody: '{"data": {"deleteAddress": {"error": null}}}',
  });
  assert.equal(r.flagged, true);
  assert.equal(r.mutation, "deleteAddress");
  assert.equal(r.severity, "low");
  assert.match(r.reason, /impossible id/);
});

test("classify does not flag the fixed lab exchange", () => {
  const r = classify({
    path: "/graphql",
    requestBody: DELETE_REQ,
    responseBody: '{"data": {"deleteAddress": {"error": {"detail": "address not found"}}}}',
  });
  assert.equal(r.flagged, false);
});

test("classify ignores non-GraphQL traffic", () => {
  const r = classify({
    path: "/api/v2/addresses/1",
    requestBody: "{}",
    responseBody: '{"ok":true}',
  });
  assert.equal(r.flagged, false);
  assert.equal(r.reason, "not a GraphQL exchange");
});

test("classify ignores queries even on the graphql path", () => {
  const r = classify({
    path: "/graphql",
    requestBody: JSON.stringify({ query: "{ addresses { id } }" }),
    responseBody: '{"data":{"addresses":[]}}',
  });
  assert.equal(r.flagged, false);
  assert.equal(r.reason, "not a mutation");
});

test("classify downgrades a non-state-changing mutation to info", () => {
  const r = classify({
    path: "/graphql",
    requestBody: JSON.stringify({ query: 'mutation { ping(id: "x") { error { detail } } }' }),
    responseBody: '{"data": {"ping": {"error": null}}}',
  });
  assert.equal(r.flagged, true);
  assert.equal(r.severity, "info");
});

test("classify survives missing input", () => {
  assert.equal(classify(undefined).flagged, false);
  assert.equal(classify({}).flagged, false);
});
