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

/**
 * Copies a failure CSV and the artifacts it references into an empty sandbox directory,
 * so the Copilot CLI never sees the job workspace.
 *
 * Usage: stage-analysis-input.cjs <csv-path> <destination-dir>
 *
 * - Only repository-relative entries that stay inside the current directory are staged.
 * - Folder entries are copied recursively; file entries copy their parent folder.
 * - Only regular files up to MAX_FILE_BYTES are copied; symbolic links are never followed.
 * - Overlapping entries (a folder and a nested folder) are safe: staged files are not copied again.
 */

const fs = require("node:fs");
const path = require("node:path");

const MAX_FILE_BYTES = 2 * 1024 * 1024;

const [csvArg, destinationArg] = process.argv.slice(2);
if (!csvArg || !destinationArg) {
  console.error("Usage: stage-analysis-input.cjs <csv-path> <destination-dir>");
  process.exit(2);
}

const sourceRoot = fs.realpathSync(process.cwd());
const destinationRoot = path.resolve(destinationArg);

function escapesSource(relative) {
  return relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative);
}

function insideSource(relativePath) {
  if (!relativePath || path.isAbsolute(relativePath)) {
    return null;
  }
  const absolutePath = path.resolve(sourceRoot, relativePath);
  const relative = path.relative(sourceRoot, absolutePath);
  if (!relative || escapesSource(relative)) {
    return null;
  }
  // Reject entries reached through a symlinked parent directory.
  let realParent;
  try {
    realParent = fs.realpathSync(path.dirname(absolutePath));
  } catch {
    return null;
  }
  const realRelative = path.relative(sourceRoot, realParent);
  if (escapesSource(realRelative)) {
    return null;
  }
  return relative;
}

function copyEntry(relativePath) {
  const sourcePath = path.join(sourceRoot, relativePath);
  const stat = fs.lstatSync(sourcePath, { throwIfNoEntry: false });
  if (!stat || stat.isSymbolicLink()) {
    return;
  }
  const targetPath = path.join(destinationRoot, relativePath);
  if (stat.isDirectory()) {
    fs.mkdirSync(targetPath, { recursive: true });
    for (const child of fs.readdirSync(sourcePath)) {
      copyEntry(path.join(relativePath, child));
    }
  } else if (stat.isFile() && stat.size <= MAX_FILE_BYTES) {
    if (fs.lstatSync(targetPath, { throwIfNoEntry: false })) {
      return;
    }
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.copyFileSync(sourcePath, targetPath, fs.constants.COPYFILE_EXCL);
  }
}

function parseCsvEntries(content) {
  return (content.match(/"(?:[^"]|"")*"|[^\r\n]+/gu) ?? [])
    .slice(1)
    .map(field => field.startsWith('"') && field.endsWith('"')
        ? field.slice(1, -1).replaceAll('""', '"')
        : field.trim())
    .filter(Boolean);
}

const csvPath = insideSource(csvArg);
if (!csvPath) {
  console.error(`CSV path must be relative to the working directory: ${csvArg}`);
  process.exit(2);
}

fs.mkdirSync(destinationRoot, { recursive: true });
copyEntry(csvPath);

const staged = new Set();
for (const entry of parseCsvEntries(fs.readFileSync(path.join(sourceRoot, csvPath), "utf8"))) {
  const relativePath = insideSource(entry);
  if (!relativePath) {
    console.warn(`Skipping entry outside the working directory: ${entry}`);
    continue;
  }
  const stat = fs.lstatSync(path.join(sourceRoot, relativePath), { throwIfNoEntry: false });
  const folder = stat?.isFile() ? path.dirname(relativePath) : relativePath;
  if (folder === "." || staged.has(folder)) {
    continue;
  }
  staged.add(folder);
  copyEntry(folder);
}

console.log(`Staged ${staged.size} failure folder(s) for analysis.`);
