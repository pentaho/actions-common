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

const fs = require("node:fs");
const path = require("node:path");
const { classifyTests } = require("../analyze-playwright-failures/playwright-outcomes.cjs");
const { issueFromAnnotations, resolveSourceFilePath } = require("../analyze-playwright-failures/generate-expected-md.cjs");

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES = 20 * 1024 * 1024;
const MAX_FILES = 1000;
const SOURCE_EXTENSION = /\.(?:[cm]?[jt]sx?)$/u;

const output = process.argv[2];
if (!output) {
  console.error("Usage: collect.cjs <output-file>");
  process.exit(2);
}

const root = fs.realpathSync(process.cwd());
const sources = new Set();
let totalBytes = 0;
for (const test of classifyTests(root).tests) {
  if (test.category !== "expected" || issueFromAnnotations(test.annotations)) {
    continue;
  }
  const source = resolveSourceFilePath(test.reportPath, test.location, test.reportedRootDir);
  if (!source) {
    continue;
  }
  const relative = path.relative(root, source);
  const segments = relative.split(path.sep);
  if (!relative || path.isAbsolute(relative) || segments.some(segment =>
    segment === ".." || segment.startsWith(".") || segment === "node_modules")
    || !SOURCE_EXTENSION.test(relative) || sources.has(relative)) {
    continue;
  }
  const stat = fs.lstatSync(source);
  if (!stat.isFile() || stat.size > MAX_FILE_BYTES) {
    continue;
  }
  if (sources.size >= MAX_FILES || totalBytes + stat.size > MAX_TOTAL_BYTES) {
    console.warn("::warning::Playwright source packaging limit reached; remaining source files were not included.");
    break;
  }
  sources.add(relative);
  totalBytes += stat.size;
}

const entries = [...sources].sort().map(source => `.${path.sep}${source}\0`).join("");
fs.writeFileSync(output, entries);
