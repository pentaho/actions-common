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
// Resolves the CTRF report glob and template using container-local paths.
"use strict";

const fs = require("fs");
const path = require("path");

function main() {
  // ctrf-io/github-test-reporter expands report-path with the glob package (minimatch semantics:
  // braces, extglobs, **, no dotfiles). fs.globSync uses the same matcher, so the existence check
  // and the reporter agree on which files a pattern selects.
  if (typeof fs.globSync !== "function") {
    throw new Error(`Node ${process.versions.node} lacks fs.globSync; Node 22 or later is required to resolve CTRF report globs.`);
  }
  const workspace = process.env.GITHUB_WORKSPACE;
  if (!workspace) throw new Error("GITHUB_WORKSPACE is required.");
  let pattern = process.env.REPORT_PATH ||
    `${(process.env.SEARCH_DIRECTORY || ".").replace(/\/+$/, "")}/**/ctrf-report.json`;
  if (!path.isAbsolute(pattern)) pattern = path.join(workspace, pattern);

  let template = process.env.REPORT_TEMPLATE_PATH ||
    path.join(process.env.GITHUB_ACTION_PATH || __dirname, "custom-report.hbs");
  if (!path.isAbsolute(template)) template = path.join(workspace, template);

  const found = fs.globSync(pattern).some(file => {
    try {
      return fs.statSync(file).isFile();
    } catch {
      return false;
    }
  });
  if (found) {
    let readable = false;
    try {
      readable = fs.statSync(template).isFile();
      fs.accessSync(template, fs.constants.R_OK);
    } catch {
      readable = false;
    }
    if (!readable) throw new Error(`CTRF report template is not readable: ${template}`);
  } else {
    console.log("No CTRF report files found. Skipping CTRF report publishing.");
  }

  if (!process.env.GITHUB_OUTPUT) throw new Error("GITHUB_OUTPUT is required.");
  fs.appendFileSync(process.env.GITHUB_OUTPUT,
    `found=${found}\nreport_path=${pattern}\ntemplate_path=${template}\n`);
}

try {
  main();
} catch (error) {
  console.error(`::error::${error.message}`);
  process.exitCode = 1;
}
