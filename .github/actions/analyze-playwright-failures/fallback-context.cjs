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

const { mkdirSync, writeFileSync } = require("node:fs");
const { resolve } = require("node:path");

const ANSI_PATTERN = /\u001b\[[0-9;]*[A-Za-z]/gu;

/**
 * Wraps text in a Markdown code fence longer than any backtick run inside it.
 * @param {string} text Text to fence.
 * @returns {string} Fenced text.
 */
function fence(text) {
  const longestRun = Math.max(2, ...(text.match(/`+/gu) ?? []).map(run => run.length));
  const marker = "`".repeat(longestRun + 1);
  return `${marker}\n${text}\n${marker}`;
}

/**
 * Builds an error-context.md substitute from Playwright report data.
 * @param {object} test Classified Playwright test.
 * @param {"Flaky" | "Unexpected"} category Failure category.
 * @returns {string} Markdown content.
 */
function buildFallbackContext(test, category) {
  const errors = test.errors
    .map(error => [error.message, error.stack].filter(Boolean).join("\n").replace(ANSI_PATTERN, "").trim())
    .filter(Boolean);
  return [
    "# Test info",
    "",
    `- Name: ${test.name}`,
    `- Location: ${test.location}`,
    `- Source: Playwright JSON report (${category.toLowerCase()} failure)`,
    `- Expected status: ${test.expectedStatus || "(not reported)"}`,
    `- Actual status: ${test.actualStatuses.length ? test.actualStatuses.join(", ") : "(not reported)"}`,
    ...(test.expectedStatus === "failed" && test.actualStatuses.includes("passed")
      ? ["- Outcome: Test passed despite being expected to fail."] : []),
    "",
    "# Error details",
    "",
    errors.length > 0 ? errors.map(fence).join("\n\n") : "No error details were reported.",
    ""
  ].join("\n");
}

/**
 * Writes a fallback error-context file and returns its containing folder.
 * @param {string} root Directory for generated contexts.
 * @param {object} test Classified Playwright test.
 * @param {"Flaky" | "Unexpected"} category Failure category.
 * @param {number} index Stable, 1-based test index.
 * @returns {string} Absolute folder containing error-context.md.
 */
function writeFallbackContext(root, test, category, index) {
  const folder = resolve(root, String(index).padStart(3, "0"));
  mkdirSync(folder, { recursive: true });
  writeFileSync(resolve(folder, "error-context.md"), buildFallbackContext(test, category), "utf8");
  return folder;
}

module.exports = { writeFallbackContext };
