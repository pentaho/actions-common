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

const { resolve } = require("node:path");
const { existsSync, realpathSync, rmSync, writeFileSync } = require("node:fs");

const {
  getCandidateFolders,
  toCsvField,
  toPosixRelativePath
} = require("./failure-report-utils.cjs");
const { selectTests } = require("./playwright-outcomes.cjs");
const { writeFallbackContext } = require("./fallback-context.cjs");

/**
 * Generates flaky-list.csv from Playwright JSON reports.
 * Writes file to repo root, or removes stale file when no flaky tests exist.
 *
 * Rule:
 * - a test is flaky only when Playwright reports its final status as "flaky"
 *   (it failed and then passed on retry); artifact layout is never used to classify
 * - lists the output folders of its failed attempts that match the report output patterns
 * - when no failed-attempt error-context exists, writes one from JSON report metadata and errors
 */

const reportOutputPath = process.argv[2] || "*/playwright-report/*/output/*";
const repoRoot = process.cwd();
const realRepoRoot = realpathSync(repoRoot);
const flakyListFile = resolve(repoRoot, "flaky-list.csv");
const fallbackContextDir = resolve(realRepoRoot, "flaky-failure-context");

/**
 * Collects the failed-attempt folders of flaky tests.
 * @param {string[]} candidateFolders Absolute folders matched by the report output patterns.
 * @returns {string[]} Repository-relative folder paths for CSV output.
 */
function collectFlakyFolders(candidateFolders) {
  const tests = selectTests(repoRoot, "flaky", candidateFolders);
  const folders = [];
  for (const [index, test] of tests.entries()) {
    folders.push(...test.folders);
    folders.push(writeFallbackContext(fallbackContextDir, test, "Flaky", index + 1));
  }
  return [...new Set(folders)].map(folderPath => toPosixRelativePath(folderPath, realRepoRoot));
}

/**
 * Renders folder list as CSV content.
 * @param {string[]} flakyFolders Repository-relative folder paths to render.
 * @returns {string} CSV content for flaky-list.csv.
 */
function buildFlakyFoldersCsv(flakyFolders) {
  const lines = [
    "folderPath",
    ...flakyFolders.map(folderPath => toCsvField(folderPath))
  ];

  return `${lines.join("\n")}\n`;
}

// Evaluate and write output at script startup. When no flaky folders exist,
// remove stale CSV from previous runs instead of leaving outdated results.
async function main() {
  rmSync(fallbackContextDir, { recursive: true, force: true });
  const candidateFolders = await getCandidateFolders(reportOutputPath, repoRoot);
  const flakyFolders = collectFlakyFolders(candidateFolders);

  if (flakyFolders.length === 0) {
    if (existsSync(flakyListFile)) {
      rmSync(flakyListFile);
    }

    console.log("No flaky folders found.");
  } else {
    writeFileSync(flakyListFile, buildFlakyFoldersCsv(flakyFolders), "utf8");
    console.log(`Generated ${toPosixRelativePath(flakyListFile, repoRoot)}.`);
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
