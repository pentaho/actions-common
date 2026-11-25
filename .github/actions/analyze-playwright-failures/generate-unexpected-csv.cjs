#!/usr/bin/env node
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

const { existsSync, realpathSync, rmSync, writeFileSync } = require("node:fs");
const { resolve } = require("node:path");

const {
  getCandidateFolders,
  toCsvField,
  toPosixRelativePath
} = require("./failure-report-utils.cjs");
const { selectTests } = require("./playwright-outcomes.cjs");
const { writeFallbackContext } = require("./fallback-context.cjs");

/**
 * Generates unexpected-failures-list.csv from Playwright JSON reports.
 * Writes file to repo root, or removes stale file when no unexpected failures exist.
 *
 * Unexpected failure rules:
 * - a test is unexpected only when Playwright reports its final status as "unexpected"
 *   (with or without retries); artifact layout is never used to classify
 * - lists error-context.md, or the artifact folder when it has no error context, for relevant attempts
 * - when a test has no such file (e.g. API assertion failures), writes a fallback error-context.md
 *   under unexpected-failure-context/ from the report's test metadata and errors, and lists it
 */

const reportOutputPath = process.argv[2] || "*/playwright-report/*/output/*";
const repoRoot = process.cwd();
const realRepoRoot = realpathSync(repoRoot);
const unexpectedFailuresFile = resolve(repoRoot, "unexpected-failures-list.csv");
const fallbackContextDir = resolve(realRepoRoot, "unexpected-failure-context");
/**
 * Collects error-context.md or artifact folder paths of unexpected failures.
 * @param {string[]} candidateFolders Absolute folders matched by the report output patterns.
 * @returns {string[]} Repository-relative context or artifact folder paths.
 */
function collectUnexpectedFailures(candidateFolders) {
  const unexpectedFailures = [];

  const tests = selectTests(repoRoot, "unexpected", candidateFolders);
  for (const [index, test] of tests.entries()) {
    const errorContextPaths = test.folders
      .map(folderPath => resolve(folderPath, "error-context.md"))
      .filter(errorContextPath => existsSync(errorContextPath));
    const artifactOnlyFolders = test.folders.filter(folderPath =>
      !existsSync(resolve(folderPath, "error-context.md")));
    const fallbackFolder = writeFallbackContext(fallbackContextDir, test, "Unexpected", index + 1);
    const fallbackPath = resolve(fallbackFolder, "error-context.md");
    unexpectedFailures.push(toPosixRelativePath(fallbackPath, realRepoRoot));
    if (errorContextPaths.length === 0) {
      console.log(`Using Playwright report details for unexpected failure: ${test.name}`);
    }
    for (const errorContextPath of errorContextPaths) {
      unexpectedFailures.push(toPosixRelativePath(errorContextPath, realRepoRoot));
    }
    for (const folderPath of artifactOnlyFolders) {
      unexpectedFailures.push(toPosixRelativePath(folderPath, realRepoRoot));
    }
  }

  return [...new Set(unexpectedFailures)];
}

/**
 * Renders unexpected failures as CSV content.
 * @param {string[]} unexpectedFailures Repository-relative context or artifact folder paths to render.
 * @returns {string} CSV content for unexpected-failures-list.csv.
 */
function buildUnexpectedFailuresCsv(unexpectedFailures) {
  const lines = [
    "errorContextPath",
    ...unexpectedFailures.map(errorContextPath => toCsvField(errorContextPath))
  ];

  return `${lines.join("\n")}\n`;
}

// Evaluate and write output at script startup. When no unexpected failures exist,
// remove stale CSV from previous runs instead of leaving outdated results.
async function main() {
  rmSync(fallbackContextDir, { recursive: true, force: true });
  const candidateFolders = await getCandidateFolders(reportOutputPath, repoRoot);
  const unexpectedFailures = collectUnexpectedFailures(candidateFolders);

  if (unexpectedFailures.length === 0) {
    if (existsSync(unexpectedFailuresFile)) {
      rmSync(unexpectedFailuresFile);
    }

    console.log("No unexpected failures found.");
  } else {
    const unexpectedFailuresCsv = buildUnexpectedFailuresCsv(unexpectedFailures);
    writeFileSync(unexpectedFailuresFile, unexpectedFailuresCsv, "utf8");
    console.log(`Generated ${toPosixRelativePath(unexpectedFailuresFile, repoRoot)}.`);
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
