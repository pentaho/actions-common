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

const { spawn } = require("node:child_process");
const { lstatSync } = require("node:fs");
const { dirname, resolve } = require("node:path");

/**
 * Escapes single quotes for safe use in single-quoted shell strings.
 * @param {unknown} value Value to quote.
 * @returns {string} Shell-quoted value.
 */
function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

/**
 * Converts repository-local absolute path to repo-relative POSIX-style path.
 * Assumes input path is rooted under repoRoot.
 * @param {string} absPath Absolute path to normalize.
 * @param {string} repoRoot Repository root path.
 * @returns {string} Relative path using forward slashes.
 */
function toPosixRelativePath(absPath, repoRoot) {
  const relativePath = absPath.replace(`${repoRoot}/`, "");
  return relativePath.replaceAll("\\", "/");
}

/**
 * Escapes and wraps a value for CSV output.
 * @param {string} value Value to escape for CSV.
 * @returns {string} CSV-safe field value.
 */
function toCsvField(value) {
  return `"${String(value).replaceAll('"', '""')}"`;
}

/**
 * Finds files and folders that match one or more find -path patterns.
 * Accepts a comma-separated list of patterns, supports patterns with and
 * without ./ prefix, then de-duplicates overlaps.
 * Streams discovery output without a fixed stdout buffer.
 * @param {string} pathPattern Comma-separated patterns used by find -path.
 * @returns {Promise<string[]>} Unique matching entries, as emitted by find.
 */
async function findMatchingEntries(pathPattern) {
  const patterns = pathPattern
    .split(",")
    .map(pattern => pattern.trim())
    .filter(Boolean);

  if (patterns.length === 0) {
    return [];
  }

  const candidates = Array.from(
    new Set(
      patterns.flatMap(pattern =>
        pattern.startsWith("./") ? [pattern] : [pattern, `./${pattern}`]
      )
    )
  );

  const pathExpression = candidates.flatMap((candidatePattern, index) =>
    [...(index === 0 ? [] : ["-o"]), "-path", candidatePattern]
  );
  const args = [".", "(", ...pathExpression, ")", "(", "-type", "d", "-o", "-type", "f", ")", "-print0"];

  return new Promise((resolveEntries, reject) => {
    const child = spawn("find", args, { stdio: ["ignore", "pipe", "inherit"] });
    const entries = new Set();
    let pending = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", chunk => {
      const paths = (pending + chunk).split("\0");
      pending = paths.pop();
      for (const entry of paths) {
        entries.add(entry);
      }
    });
    child.stdout.on("error", reject);
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (code !== 0) {
        reject(new Error(`find discovery failed (${signal ? `signal ${signal}` : `exit code ${code}`}).`));
      } else {
        resolveEntries(Array.from(entries));
      }
    });
  });
}

/**
 * Converts matched entries into unique absolute folder paths.
 * File matches are normalized to their parent folder. Unreadable matches are skipped.
 * @param {string} pathPattern Pattern used by find -path.
 * @param {string} repoRoot Repository root path.
 * @returns {Promise<string[]>} Sorted absolute folder paths.
 */
async function getCandidateFolders(pathPattern, repoRoot) {
  const matchedEntries = await findMatchingEntries(pathPattern);

  return Array.from(
    new Set(
      matchedEntries
        .map(entry => {
          const absoluteEntry = resolve(repoRoot, entry);

          try {
            return lstatSync(absoluteEntry).isDirectory()
              ? absoluteEntry
              : dirname(absoluteEntry);
          } catch (error) {
            console.warn(
              `Skipping unreadable entry: ${entry} (${error.message})`
            );
            return undefined;
          }
        })
        .filter(Boolean)
    )
  ).sort((a, b) => a.localeCompare(b));
}

module.exports = { shellQuote, toPosixRelativePath, toCsvField, findMatchingEntries, getCandidateFolders };
