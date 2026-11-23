"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Handlebars = require("handlebars");

async function main() {
  const { loadHelpers } = await import("handlebars-helpers-ctrf");
  loadHelpers(Handlebars);
  Handlebars.registerHelper("sliceString", (value, start, end) => value.slice(start, end));
  Handlebars.registerHelper("splitLines", value => (value || "").split("\n").filter(Boolean));
  Handlebars.registerHelper("formatTestPath", (suite, name) => new Handlebars.SafeString(`${suite} > ${name}`));
  Handlebars.registerHelper("anyFailedTests", tests => tests.some(test => test.status === "failed"));

  const source = fs.readFileSync(path.join(__dirname, "../../actions/playwright-test-summary/custom-report.hbs"), "utf8");
  const render = Handlebars.compile(source, { preventIndent: true });
  const context = {
    ctrf: {
      summary: { tests: 6, suites: 2, passed: 1, failed: 2, skipped: 1, pending: 1, other: 1, start: 1000, stop: 5000 },
      tests: [
        { name: "expected failure", status: "passed", suite: "chrome" },
        { name: "retry success", status: "passed", flaky: true, suite: "chrome" },
        { name: "unexpected failure", status: "failed", suite: "chrome" },
        { name: "skipped test", status: "skipped", suite: "firefox" },
        { name: "pending test", status: "pending", suite: "firefox" },
        { name: "other test", status: "other", suite: "firefox" }
      ],
      tool: { name: "Playwright" },
      environment: {
        appName: "Pentaho", appVersion: "11.0", buildName: "pdia-master",
        buildNumber: "42", buildUrl: "https://github.com/owner/repo/actions/runs/42",
        branchName: "feature", testEnvironment: "sample"
      }
    },
    report: { insights: { extra: { summary: {
      failed: { change: 1 }, passed: { change: -1 }, tests: { change: 1 }, duration: { change: -1000 }
    } } } },
    github: {
      workflow: "Scheduler tests", pullRequestNumber: 12,
      pullRequest: { title: "Fix Scheduler", htmlUrl: "https://github.com/owner/repo/pull/12" },
      repository: { htmlUrl: "https://github.com/owner/repo" }
    }
  };
  const markdown = render(context);
  for (const text of [
    "2 all failures (including expected failures)", "1 passed", "1 skipped",
    "1 pending", "1 other", "1 flaky", "6 tests", "2 suites", "Playwright",
    "Pentaho v11.0", "pdia-master", "Fix Scheduler", "Unexpected Failures",
    "Flaky Tests", "Skipped Tests", "Pending Tests", "Other Tests",
    "chrome > unexpected failure", "chrome > retry success", "firefox > skipped test",
    "firefox > pending test", "firefox > other test", "↑1", "↓1", "sample"
  ]) {
    assert.ok(markdown.includes(text), `Missing report feature: ${text}`);
  }
  assert.ok(!markdown.includes("chrome > expected failure"), "Expected failures must not appear as unexpected failures");
  const expectedFailuresOnly = render({
    ...context,
    report: {},
    ctrf: {
      ...context.ctrf,
      summary: { tests: 1, suites: 1, passed: 0, failed: 1, skipped: 0, pending: 0, other: 0, start: 1000, stop: 5000 },
      tests: [{ name: "expected failure", status: "passed", suite: "chrome" }]
    }
  });
  assert.ok(expectedFailuresOnly.includes("1 all failures (including expected failures)"),
    "Expected failures must remain included in the raw failure count");
  assert.ok(!expectedFailuresOnly.includes("Unexpected Failures"),
    "Expected failures alone must not create an empty Unexpected Failures section");
  assert.ok(!expectedFailuresOnly.includes("chrome > expected failure"),
    "Expected failures must not be listed as unexpected failures");
  const withoutHistory = render({ ...context, report: {} });
  assert.ok(!withoutHistory.includes("↑") && !withoutHistory.includes("↓"),
    "Without historical insights the report must not show trend arrows");

  // Scheduled and manually dispatched runs: the reporter exposes the tested commit only as the root
  // github.sha; the event payload (github.context) has no commits array.
  context.github = {
    workflow: "Nightly", eventName: "schedule", event_name: "schedule",
    sha: "abcdef1234567890abcdef1234567890abcdef12", ref: "refs/heads/feature",
    repository: { htmlUrl: "https://github.com/owner/repo", html_url: "https://github.com/owner/repo" },
    pullRequest: {}, sender: {},
    context: { schedule: "0 2 * * *" }
  };
  const nightly = render(context);
  assert.ok(nightly.includes(
    "[abcdef1](https://github.com/owner/repo/commit/abcdef1234567890abcdef1234567890abcdef12)"),
    "Nightly report must link the tested commit from github.sha");
  assert.ok(nightly.includes("/tree/feature"));

  context.github = { ...context.github, eventName: "workflow_dispatch", event_name: "workflow_dispatch",
    context: { inputs: {}, ref: "refs/heads/feature" } };
  assert.ok(render(context).includes("[abcdef1](https://github.com/owner/repo/commit/"),
    "Manually dispatched report must link the tested commit from github.sha");

  context.github = { ...context.github, repository: {} };
  const unlinked = render(context);
  assert.ok(unlinked.includes("`abcdef1`") && !unlinked.includes("](#)"),
    "Without a repository URL the commit is shown without a dead link");

  context.github = {
    workflow: "Push", sha: "1111111aaaaaaa", repository: { htmlUrl: "https://github.com/owner/repo" },
    context: { commits: [{ id: "2222222bbbbbbb", message: "Push commit\nCommit details",
                           url: "https://github.com/owner/repo/commit/2222222bbbbbbb" }] }
  };
  const push = render(context);
  assert.ok(push.includes("Push commit") && !push.includes("Commit details"));
  assert.ok(push.includes("[2222222](https://github.com/owner/repo/commit/2222222bbbbbbb)"));
  assert.ok(!push.includes("1111111"), "Event commits take precedence over github.sha");

  context.ctrf.summary = { tests: 0, passed: 0, failed: 0, skipped: 0, pending: 0, other: 0, start: 0, stop: 0 };
  context.ctrf.tests = [];
  const empty = render(context);
  for (const heading of ["Unexpected Failures", "Flaky Tests", "Skipped Tests", "Pending Tests", "Other Tests"]) {
    assert.ok(!empty.includes(heading), `Empty report contains ${heading}`);
  }
  console.log("CTRF template rendering checks passed");
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
