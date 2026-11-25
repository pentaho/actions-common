/* ******************************************************************************
 *
 * Pentaho
 *
 * Copyright (C) 2026 by Pentaho Canada Inc. : http://www.pentaho.com
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file.
 *
 * Change Date: 2030-06-15
 ****************************************************************************** */
"use strict";

const fs = require("fs");
const path = require("path");
const { randomUUID } = require("crypto");

const SKIPPED_DIRS = new Set(["node_modules", ".git"]);

function walk(dir, visit, insideReportDir = false) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (error) {
    console.warn(`::warning::Unable to search ${dir}: ${error.message}`);
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRS.has(entry.name)) {
        walk(full, visit, insideReportDir || entry.name === "playwright-report");
      }
    } else if (entry.isFile()) {
      visit(full, entry.name, insideReportDir);
    }
  }
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    console.warn(`::warning::Unable to parse ${file}: ${error.message}`);
    return undefined;
  }
}

function collect(root) {
  const ctrf = [];
  const playwright = [];
  walk(root, (file, name, insideReportDir) => {
    if (name === "ctrf-report.json") {
      ctrf.push(file);
    } else if (insideReportDir && name.endsWith(".json")) {
      playwright.push(file);
    }
  }, path.basename(root) === "playwright-report");
  return { ctrf: ctrf.sort(), playwright: playwright.sort() };
}

function suiteParts(suite) {
  const parts = Array.isArray(suite) ? suite : typeof suite === "string" ? suite.split(" > ") : [];
  return parts.filter(part => typeof part === "string").map(part => part.trim()).filter(Boolean);
}

function titleCase(value) {
  return value.split(/[-_\s]+/).filter(Boolean).map(word => word[0].toUpperCase() + word.slice(1)).join(" ");
}

// Module = first folder of the report path below the search root (e.g. "browse-files/automation/...").
function moduleName(root, file) {
  const [first, ...rest] = path.relative(root, file).split(path.sep);
  return rest.length > 0 ? titleCase(first) : "";
}

function summarize(root, groupBy = "browser") {
  const count = () => ({ total: 0, passed: 0, failed: 0, skipped: 0 });
  const totals = count();
  const browsers = Object.create(null);
  const { ctrf, playwright } = collect(root);
  const parsed = [];

  for (const file of ctrf) {
    const tests = readJson(file)?.results?.tests;
    if (!Array.isArray(tests)) {
      console.warn(`::warning::No CTRF tests array in ${file}.`);
      continue;
    }
    // Per-test statuses include expected failures as passed; raw CTRF summary counts do not.
    // CTRF suites are either "project > file > title" strings or arrays starting with the project.
    for (const { status, suite, browser: reportedBrowser } of tests.filter(test => test && typeof test === "object")) {
      const [project] = suiteParts(suite);
      if (project === "setup") continue;
      const explicitBrowser = typeof reportedBrowser === "string" ? reportedBrowser.trim() : "";
      let browser = explicitBrowser || project || "Tests";
      if (groupBy === "module") {
        const module = moduleName(root, file);
        if (module) browser = `${module} - ${browser[0].toUpperCase()}${browser.slice(1)}`;
      }
      const key = ["pending", "skipped"].includes(status)
        ? "skipped"
        : status === "passed" ? "passed" : "failed";
      for (const counts of [totals, (browsers[browser] ??= count())]) {
        counts.total++;
        counts[key]++;
      }
    }
    parsed.push(file);
  }

  if (parsed.length === 0) {
    const countSuite = suite => {
      for (const spec of suite.specs || []) {
        for (const test of spec.tests || []) {
          if (test.projectName === "setup") continue;
          const key = test.status === "skipped"
            ? "skipped"
            : ["expected", "flaky"].includes(test.status) ? "passed" : "failed";
          totals.total++;
          totals[key]++;
        }
      }
      for (const child of suite.suites || []) countSuite(child);
    };
    for (const file of playwright) {
      const report = readJson(file);
      if (!Array.isArray(report?.suites)) continue;
      for (const suite of report.suites) countSuite(suite);
      parsed.push(file);
    }
  }

  return { totals, browsers, parsed, ctrfFound: ctrf.length > 0 && parsed.some(file => ctrf.includes(file)) };
}

function main() {
  const root = path.resolve(process.env.SEARCH_DIRECTORY || ".");
  const summaryFormat = process.env.SUMMARY_FORMAT || "compact";
  if (!["compact", "multiline"].includes(summaryFormat)) {
    throw new Error(`Unsupported summary format: ${summaryFormat}`);
  }
  const groupBy = process.env.SUMMARY_GROUP_BY || "browser";
  if (!["browser", "module"].includes(groupBy)) {
    throw new Error(`Unsupported summary grouping: ${groupBy}`);
  }
  const { totals, browsers, parsed, ctrfFound } = summarize(root, groupBy);
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  let guideLink = "";
  if (process.env.REPORT_GUIDE_PATH) {
    const guidePath = path.resolve(workspace, process.env.REPORT_GUIDE_PATH);
    const relative = path.relative(workspace, guidePath);
    if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
      throw new Error("The report guide must be inside the caller's repository.");
    }
    if (!fs.statSync(guidePath).isFile()) throw new Error("The report guide must be a file.");
    const repository = process.env.GUIDE_REPOSITORY;
    const ref = process.env.GUIDE_REF;
    if (!repository || !ref) throw new Error("The report guide requires a repository and ref.");
    const url = `${process.env.GITHUB_SERVER_URL || "https://github.com"}/${repository}/blob/${encodeURIComponent(ref)}/${relative.split(path.sep).map(encodeURIComponent).join("/")}`;
    guideLink = `[How to inspect failure details locally](${url})`;
  }
  const found = parsed.length > 0;
  const line = (name, counts) =>
    `${name}: ${counts.total} total, ✅ ${counts.passed} passed, ❌ ${counts.failed} failed, ⏭️ ${counts.skipped} skipped`;
  const browserLines = Object.entries(browsers).map(([name, counts]) =>
    line(summaryFormat === "multiline" ? name[0].toUpperCase() + name.slice(1) : name, counts));
  const summary = found
    ? browserLines.join(summaryFormat === "multiline" ? "\n" : "; ") || line("Tests", totals)
    : "Tests: no results found";

  console.log(summary);
  if (process.env.VERBOSE === "true") {
    for (const file of parsed) console.log(`  parsed ${path.relative(root, file) || file}`);
  }

  const versionFile = path.resolve(root, process.env.SERVER_VERSION_FILE || "src/resources/.auth/server-version.json");
  let version = "";
  if (fs.existsSync(versionFile)) {
    const value = readJson(versionFile)?.version;
    if (typeof value === "string" && /^[0-9][A-Za-z0-9.+_-]*$/.test(value)) {
      version = value.replace(/^(\d+(?:\.\d+){3})\.(\d+)$/, "$1-$2");
    }
  }
  if (!version) console.warn(`::warning::No platform version found in ${versionFile}; Practitest upload will be skipped.`);
  console.log(`Pentaho Server version: ${version || "unknown"}`);

  if (process.env.GITHUB_OUTPUT) {
    const lines = Object.entries(totals).map(([key, value]) => `${key}=${value}`);
    lines.push(`found=${found}`, `ctrf_found=${ctrfFound}`, `server_version=${version}`);
    const delimiter = randomUUID();
    lines.push(`summary<<${delimiter}`, summary, delimiter);
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${lines.join("\n")}\n`);
  }

  if (process.env.GITHUB_STEP_SUMMARY) {
    const markdown = found
      ? [
          "## Playwright test results",
          "",
          "| Total | Passed | Failed | Skipped |",
          "| ---: | ---: | ---: | ---: |",
          `| ${totals.total} | ${totals.passed} | ${totals.failed} | ${totals.skipped} |`,
          "",
          ...browserLines,
          "",
          `Pentaho Server version: ${version || "unknown"}`,
          ""
        ]
      : ["## Playwright test results", "", "No test results found.", ""];
    markdown.push(
      `## ${guideLink || "How to inspect failure details locally"}`,
      "",
      "If available, download and extract the Playwright HTML report artifact from this workflow run.",
      "Open the extracted HTML report with Playwright, or open a retained trace file:",
      "",
      "```sh",
      "npx playwright show-report path/to/playwright-report",
      "npx playwright show-trace path/to/trace.zip",
      "```",
      ""
    );
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${markdown.join("\n")}\n`);
  }
}

try {
  main();
} catch (error) {
  console.error(`::error::Unable to summarize test results: ${error.message}`);
  process.exitCode = 1;
}
