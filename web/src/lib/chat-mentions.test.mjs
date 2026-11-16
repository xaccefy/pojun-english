import assert from "node:assert/strict";
import test from "node:test";
import { activeMention, mentionSearch, mentionToken, selectedMentions } from "./chat-mentions.ts";

test("mention trigger supports labels and cursor placement without hijacking email", () => {
  assert.equal(activeMention("user@example.com", 16), null);
  assert.equal(activeMention("picked @[vuln#1 X]", 13), null);
  assert.deepEqual(activeMention("ok@vuln text after it", 7), { start: 2, end: 7, query: "vuln" });
  assert.equal(activeMention("@vuln\nnext line", 8), null);
});

test("categories, aliases, IP and keyword search", () => {
  assert.equal(mentionSearch("").categories.length, 9);
  assert.equal(mentionSearch("v").categories[0].kind, "finding");
  assert.equal(mentionSearch("vuln").kind, "finding");
  assert.equal(mentionSearch("vuln SQL injection").query, "SQL injection");
  assert.equal(mentionSearch("ip 192.0.2.1").kind, "ip");
  assert.equal(mentionSearch("endpoint GET /api").query, "GET /api");
  assert.equal(mentionSearch("acme.com").kind, "");
});

test("tokens roundtrip labels and removing one reference preserves its neighbors", () => {
  const first = mentionToken({ kind: "finding", id: 12, label: "Title[1]\nDescription" });
  const second = mentionToken({ kind: "ip", id: 13, label: "192.0.2.1" });
  const value = `Analyze ${first} and ${second}`;
  const selected = selectedMentions(value);
  assert.equal(selected.length, 2);
  assert.equal(selected[0].label, "vuln #12 \u00B7 Title(1) Description");
  const next = value.slice(0, selected[0].start) + value.slice(selected[0].start + selected[0].token.length);
  assert.equal(selectedMentions(next)[0].token, second);
});
