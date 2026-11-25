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
 ******************************************************************************/
"use strict";

/**
 * Classifies Playwright tests from JSON reporter output and maps them to their artifacts.
 *
 * The category comes only from Playwright's own verdict, never from the artifact layout:
 * - expected:   expectedStatus "failed" and final status "expected" (e.g. test.fail that failed)
 * - flaky:      final status "flaky" (failed, then passed on retry)
 * - unexpected: final status "unexpected" (did not meet its expected status)
 *
 * Artifacts are the folders of the test's failed attempts, taken from attachment paths.
 * The report holds the absolute paths of the machine that ran the tests, so each folder is
 * mapped to the longest path suffix that exists under the local root.
 */

const fs = require("node:fs");
const path = require("node:path");

const SKIPPED_DIRS = new Set(["node_modules", ".git"]);
const FAILED_RESULT_STATUSES = new Set(["failed", "timedOut", "interrupted"]);

/**
 * @typedef {object} ClassifiedTest
 * @property {"expected" | "flaky" | "unexpected"} category Playwright verdict category.
 * @property {string} name Test title, prefixed with its project when present.
 * @property {string} location Test file location as file:line:column.
 * @property {string} reportPath Absolute path of the originating Playwright JSON report.
 * @property {string | undefined} reportedRootDir Playwright config.rootDir from the reporting machine.
 * @property {string} expectedStatus Expected Playwright status.
 * @property {string[]} actualStatuses Statuses of attempts relevant to the failure.
 * @property {{ type: string, description?: string }[]} annotations Test and result annotations.
 * @property {string[]} folders Local absolute folders of failed attempts, in attempt order.
 * @property {{ message?: string, stack?: string }[]} errors Errors of failed attempts, in attempt order.
 */

function escapesRoot(relative) {
  return relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative);
}

/**
 * Finds Playwright JSON reporter files: JSON files inside playwright-report folders.
 * @param {string} root Directory to search.
 * @returns {string[]} Sorted absolute report paths.
 */
function findJsonReports(root) {
  const reports = [];
  const walk = (dir, insideReportDir) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory() && !SKIPPED_DIRS.has(entry.name)) {
        walk(full, insideReportDir || entry.name === "playwright-report");
      } else if (entry.isFile() && insideReportDir && entry.name.endsWith(".json")) {
        reports.push(full);
      }
    }
  };
  walk(root, path.basename(root) === "playwright-report");
  return reports.sort();
}

/**
 * Returns the folder of a reported attachment path, whatever the reporting OS was.
 * path.dirname() follows the host rules, so a Windows path analyzed on Linux would yield ".".
 * @param {string} reportedPath Attachment path recorded in the report.
 * @returns {string} Folder path with forward slashes.
 */
function reportedDirname(reportedPath) {
  return path.posix.dirname(reportedPath.replaceAll("\\", "/"));
}

/**
 * Maps a report folder path (from another machine) to an existing local folder under root.
 * Tries the longest suffix first and requires at least two path segments.
 * @param {string} reportedFolder Absolute folder path recorded in the report.
 * @param {string} root Local root directory (real path).
 * @returns {string | undefined} Local absolute folder path.
 */
function mapReportedFolder(reportedFolder, root) {
  const parts = reportedFolder.split(/[\\/]+/u).filter(Boolean);
  for (let start = 0; start <= parts.length - 2; start++) {
    const candidate = path.resolve(root, ...parts.slice(start));
    if (escapesRoot(path.relative(root, candidate))) {
      continue;
    }
    const stat = fs.lstatSync(candidate, { throwIfNoEntry: false });
    if (!stat?.isDirectory()) {
      continue;
    }
    if (escapesRoot(path.relative(root, fs.realpathSync(candidate)))) {
      continue;
    }
    return candidate;
  }
  return undefined;
}

/**
 * Returns the Playwright verdict category of a JSON report test entry.
 * @param {{ expectedStatus?: string, status?: string }} test JSON reporter test entry.
 * @returns {"expected" | "flaky" | "unexpected" | undefined} Category, or undefined when not a failure.
 */
function categorize(test) {
  if (test.status === "unexpected") {
    return "unexpected";
  }
  if (test.status === "flaky") {
    return "flaky";
  }
  if (test.status === "expected" && test.expectedStatus === "failed") {
    return "expected";
  }
  return undefined;
}

/**
 * Reads every Playwright JSON report under root and classifies its failing tests.
 * @param {string} root Directory searched for reports and artifacts.
 * @returns {{ reports: string[], tests: ClassifiedTest[] }} Parsed reports and classified tests.
 */
function classifyTests(root) {
  const realRoot = fs.realpathSync(root);
  const reports = [];
  const tests = [];
  const seen = new Set();

  for (const reportPath of findJsonReports(realRoot)) {
    let report;
    try {
      report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    } catch {
      continue;
    }
    if (!Array.isArray(report?.suites) || !report.config
      || typeof report.config !== "object" || Array.isArray(report.config)) {
      continue;
    }
    reports.push(reportPath);

    const visit = (suite, titles) => {
      // File-level suites are titled with the file name; only describe blocks name the test.
      const suiteTitles = suite.title && suite.title !== suite.file ? [...titles, suite.title] : titles;
      for (const spec of suite.specs ?? []) {
        for (const [testIndex, test] of (spec.tests ?? []).entries()) {
          const category = categorize(test);
          const key = `${reportPath}\0${spec.id ?? spec.title}\0${test.projectId ?? test.projectName ?? ""}\0${testIndex}`;
          if (!category || seen.has(key)) {
            continue;
          }
          seen.add(key);

          const results = Array.isArray(test.results) ? test.results : [];
          const folders = [];
          const errors = [];
          const actualStatuses = [];
          for (const result of results) {
            const unexpectedPass = test.expectedStatus === "failed" && result.status === "passed";
            if ((!FAILED_RESULT_STATUSES.has(result.status) && !unexpectedPass)
                || (category === "flaky" && result.status === test.expectedStatus)) {
              continue;
            }
            actualStatuses.push(result.status);
            const resultErrors = Array.isArray(result.errors) && result.errors.length > 0
              ? result.errors
              : [result.error].filter(Boolean);
            errors.push(...resultErrors.map(error => ({ message: error?.message, stack: error?.stack })));
            for (const attachment of result.attachments ?? []) {
              if (typeof attachment?.path !== "string") {
                continue;
              }
              const folder = mapReportedFolder(reportedDirname(attachment.path), realRoot);
              if (folder && !folders.includes(folder)) {
                folders.push(folder);
              }
            }
          }

          const title = [...suiteTitles, spec.title].filter(Boolean).join(" › ");
          tests.push({
            category,
            name: test.projectName ? `[${test.projectName}] › ${title}` : title,
            location: `${spec.file ?? suite.file ?? ""}:${spec.line ?? ""}:${spec.column ?? ""}`,
            reportPath,
            reportedRootDir: typeof report.config.rootDir === "string" ? report.config.rootDir : undefined,
            expectedStatus: test.expectedStatus,
            actualStatuses,
            annotations: [
              ...(test.annotations ?? []),
              ...results.flatMap(result => result.annotations ?? [])
            ],
            folders,
            errors
          });
        }
      }
      for (const child of suite.suites ?? []) {
        visit(child, suiteTitles);
      }
    };
    for (const suite of report.suites) {
      visit(suite, []);
    }
  }

  return { reports, tests };
}

/**
 * Classifies tests, keeps one category and restricts artifacts to the allowed folders.
 * Warns when no JSON report exists, since outcomes cannot be determined without one.
 * @param {string} root Directory searched for reports and artifacts.
 * @param {"expected" | "flaky" | "unexpected"} category Category to select.
 * @param {string[]} allowedFolders Absolute folders matched by the report output patterns.
 * @returns {ClassifiedTest[]} Tests of the category with folders filtered to allowedFolders.
 */
function selectTests(root, category, allowedFolders) {
  const { reports, tests } = classifyTests(root);
  if (reports.length === 0) {
    console.log("::warning::No Playwright JSON report found under playwright-report folders; "
      + "failure outcomes cannot be determined, so no failures are classified.");
    return [];
  }
  const allowed = new Set(allowedFolders.map(folder => {
    try {
      return fs.realpathSync(folder);
    } catch {
      return folder;
    }
  }));
  return tests
    .filter(test => test.category === category)
    .map(test => ({ ...test, folders: test.folders.filter(folder => allowed.has(folder)) }));
}

module.exports = { categorize, classifyTests, findJsonReports, mapReportedFolder, reportedDirname, selectTests };
