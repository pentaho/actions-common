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
const { existsSync, realpathSync, readFileSync, rmSync, statSync, writeFileSync } = require("node:fs");
const { isAbsolute, relative, resolve, sep, win32 } = require("node:path");

const {
  getCandidateFolders,
  toPosixRelativePath
} = require("./failure-report-utils.cjs");
const { selectTests } = require("./playwright-outcomes.cjs");

/**
 * Generates expected-failures.md from Playwright JSON reports.
 * Writes file to repo root, or removes it when no expected failures exist.
 *
 * Expected failure rule:
 * - Playwright expected the test to fail (expectedStatus "failed") and its final status is
 *   "expected"; artifact layout is never used to classify
 *
 * Name and Location come from the report. The expected issue comes from the test's
 * "issue" annotation; when absent, from the failing test's declaration in the referenced
 * source file. Embedded source excerpts are not trusted because they may include neighboring tests.
 */

const reportOutputPath = process.argv[2] || "*/playwright-report/*/output/*";
const repoRoot = process.cwd();
const expectedFailuresFile = resolve(repoRoot, "expected-failures.md");
// Workspace root used by source fallback resolution when package-local files are
// not present under the generated playwright-report package path.
const workspaceRepoRoot = resolve(process.env.GITHUB_WORKSPACE || repoRoot);

/**
 * Fallback label used when no issue annotation can be extracted from either
 * the error-context file or the referenced source file.
 * @type {string}
 */
const MISSING_ISSUE_TEXT = "(missing issue)";

const MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024;

/**
 * @typedef {object} TestInfo
 * @property {string} name Playwright test name.
 * @property {string} location Test file location from error-context.
 */

/**
 * @typedef {TestInfo & { expectedIssue: string }} ExpectedFailure
 */

/**
 * Escapes markdown table separators.
 * @param {string} value Value to escape.
 * @returns {string} Escaped markdown-safe value.
 */
function markdownEscape(value) {
  return String(value).replaceAll("|", "\\|");
}

/**
 * Normalizes a matched issue description, collapsing whitespace.
 * @param {string | undefined} description Extracted issue description.
 * @returns {string} Normalized description, or fallback text when absent.
 */
function normalizeIssueDescription(description) {
  const normalized = typeof description === "string"
    ? description.replace(/\s+/g, " ").trim()
    : "";
  return normalized || MISSING_ISSUE_TEXT;
}

/**
 * Extracts test Name and Location fields from error-context markdown.
 * @param {string} errorContextContent Full error-context file content.
 * @returns {{name: string, location: string}} Parsed test info.
 */
function extractTestInfo(errorContextContent) {
  const nameMatch = errorContextContent.match(/^- Name:\s*(.+)$/m);
  const locationMatch = errorContextContent.match(/^- Location:\s*(.+)$/m);

  return {
    name: nameMatch ? nameMatch[1].trim() : "(missing Name)",
    location: locationMatch ? locationMatch[1].trim() : "(missing Location)"
  };
}

/**
 * Matches a Playwright test declaration call, e.g. `test(`, `test.fail(`, `it.only(`.
 * @type {RegExp}
 */
const TEST_CALL_PATTERN = /\b(?:test|it)(?:\.(?:only|skip|fail|fixme|slow))?\s*\(/g;

/**
 * Returns the end index of the call whose opening parenthesis is at openIndex,
 * skipping strings, template literals and comments. An ambiguous slash may start a regular
 * expression, so fail closed rather than risk consuming a neighboring test declaration.
 * @param {string} source Source text.
 * @param {number} openIndex Index of the opening parenthesis.
 * @returns {number} Index just after the matching closing parenthesis, or -1.
 */
function findCallEnd(source, openIndex) {
  // Stack of open delimiters; "`" marks template text, "${" an interpolation.
  const stack = [];
  let i = openIndex;
  while (i < source.length) {
    const char = source[i];
    const top = stack[stack.length - 1];

    if (top === "`") {
      if (char === "\\") {
        i += 2;
        continue;
      }
      if (char === "`") {
        stack.pop();
      } else if (char === "$" && source[i + 1] === "{") {
        stack.push("${");
        i += 1;
      }
      i += 1;
      continue;
    }

    if (char === "/" && source[i + 1] === "/") {
      const lineEnd = source.indexOf("\n", i);
      i = lineEnd < 0 ? source.length : lineEnd;
      continue;
    }
    if (char === "/" && source[i + 1] === "*") {
      const commentEnd = source.indexOf("*/", i + 2);
      if (commentEnd < 0) {
        return -1;
      }
      i = commentEnd + 2;
      continue;
    }
    if (char === "/") {
      return -1;
    }
    if (char === "\"" || char === "'") {
      i += 1;
      while (i < source.length && source[i] !== char && source[i] !== "\n") {
        i += source[i] === "\\" ? 2 : 1;
      }
      i += 1;
      continue;
    }
    if (char === "`") {
      stack.push("`");
    } else if (char === "(" || char === "[" || char === "{") {
      stack.push(char);
    } else if (char === ")" || char === "]" || char === "}") {
      const expected = char === ")" ? "(" : char === "]" ? "[" : "{";
      if (top !== expected && !(char === "}" && top === "${")) {
        return -1;
      }
      stack.pop();
      if (stack.length === 0) {
        return i + 1;
      }
    }
    i += 1;
  }

  return -1;
}

/**
 * Extracts the source of the test declared at the given location.
 * Playwright reports the location of the test call: the column points into its callee
 * (`test` for `test(`, `fail` for `test.fail(`). With a column, only the call whose callee
 * spans it is used; without one, the line must contain exactly one test call.
 * @param {string} sourceContent Full source file content.
 * @param {number} line 1-based line number of the test declaration.
 * @param {number} [column] 1-based column of the test declaration.
 * @returns {string | undefined} Test call source, or undefined when not identifiable.
 */
function extractTestSourceAt(sourceContent, line, column) {
  const lines = sourceContent.split("\n");
  if (!Number.isInteger(line) || line < 1 || line > lines.length) {
    return undefined;
  }
  if (column !== undefined && (!Number.isInteger(column) || column < 1)) {
    return undefined;
  }

  const lineStart = lines.slice(0, line - 1).reduce((offset, text) => offset + text.length + 1, 0);
  const lineText = lines[line - 1];
  const calls = [...lineText.matchAll(TEST_CALL_PATTERN)].map(callMatch => ({
    start: lineStart + callMatch.index,
    openIndex: lineStart + callMatch.index + callMatch[0].length - 1
  }));
  const target = lineStart + (column ?? 0) - 1;
  const candidates = column === undefined
    ? calls
    : calls.filter(call => target >= call.start && target < call.openIndex);
  if (candidates.length !== 1) {
    return undefined;
  }

  const [call] = candidates;
  const callEnd = findCallEnd(sourceContent, call.openIndex);
  return callEnd < 0 ? undefined : sourceContent.slice(call.start, callEnd);
}

/**
 * Tokenizes syntax needed for annotation objects. Ambiguous slash syntax fails closed.
 * Interpolated templates are opaque and cannot be used as annotation literals.
 * @param {string} source Source text.
 * @returns {{type: string, value: string}[] | undefined} Tokens or undefined when ambiguous.
 */
function tokenizeAnnotationSource(source) {
  const tokens = [];
  const skipQuoted = (start, quote) => {
    let index = start + 1;
    let value = "";
    let escaped = false;
    while (index < source.length && source[index] !== quote) {
      if (source[index] === "\\" && index + 1 < source.length) {
        escaped = true;
        value += source.slice(index, index + 2);
        index += 2;
      } else {
        value += source[index++];
      }
    }
    return source[index] === quote ? { end: index + 1, value, escaped } : undefined;
  };
  const skipTemplate = start => {
    let index = start + 1;
    while (index < source.length) {
      if (source[index] === "\\") {
        index += 2;
        continue;
      }
      if (source[index] === "`") {
        return index + 1;
      }
      if (source[index] === "$" && source[index + 1] === "{") {
        let depth = 1;
        index += 2;
        while (index < source.length && depth > 0) {
          const current = source[index];
          if (current === "'" || current === "\"") {
            const quoted = skipQuoted(index, current);
            if (!quoted) {
              return undefined;
            }
            index = quoted.end;
          } else if (current === "`") {
            const templateEnd = skipTemplate(index);
            if (!templateEnd) {
              return undefined;
            }
            index = templateEnd;
          } else if (current === "/" && source[index + 1] === "/") {
            const end = source.indexOf("\n", index + 2);
            index = end < 0 ? source.length : end + 1;
          } else if (current === "/" && source[index + 1] === "*") {
            const end = source.indexOf("*/", index + 2);
            if (end < 0) {
              return undefined;
            }
            index = end + 2;
          } else if (current === "/") {
            return undefined;
          } else {
            if (current === "{") {
              depth++;
            } else if (current === "}") {
              depth--;
            }
            index++;
          }
        }
        if (depth !== 0) {
          return undefined;
        }
        continue;
      }
      index++;
    }
    return undefined;
  };
  let i = 0;
  while (i < source.length) {
    const char = source[i];
    if (/\s/u.test(char)) {
      i++;
      continue;
    }
    if (char === "/" && source[i + 1] === "/") {
      const end = source.indexOf("\n", i + 2);
      i = end < 0 ? source.length : end + 1;
      continue;
    }
    if (char === "/" && source[i + 1] === "*") {
      const end = source.indexOf("*/", i + 2);
      if (end < 0) {
        return undefined;
      }
      i = end + 2;
      continue;
    }
    if (char === "/") {
      return undefined;
    }
    if (char === "'" || char === "\"" || char === "`") {
      if (char === "`") {
        const end = skipTemplate(i);
        if (!end) {
          return undefined;
        }
        const raw = source.slice(i + 1, end - 1);
        tokens.push({ type: raw.includes("${") || raw.includes("\\") ? "template" : "string", value: raw });
        i = end;
        continue;
      }
      const string = skipQuoted(i, char);
      if (!string) {
        return undefined;
      }
      tokens.push({ type: string.escaped ? "escaped-string" : "string", value: string.value });
      i = string.end;
      continue;
    }
    const identifier = source.slice(i).match(/^[\p{ID_Start}_$][\p{ID_Continue}$]*/u);
    if (identifier) {
      tokens.push({ type: "identifier", value: identifier[0] });
      i += identifier[0].length;
      continue;
    }
    tokens.push({ type: "punctuation", value: char });
    i++;
  }
  return tokens;
}

/**
 * Extracts one unambiguous issue annotation from recognized Playwright annotation locations.
 * Dynamic or otherwise ambiguous annotation values fail closed.
 * @param {string} testSource Test declaration source.
 * @returns {string} Issue description or fallback text.
 */
function extractIssueFromTestSource(testSource) {
  const tokens = tokenizeAnnotationSource(testSource);
  if (!tokens) {
    return MISSING_ISSUE_TEXT;
  }

  const pairs = new Map();
  const stack = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.type !== "punctuation") {
      continue;
    }
    if (token.value === "{" || token.value === "[" || token.value === "(") {
      stack.push({ index: i, value: token.value });
    } else if (token.value === "}" || token.value === "]" || token.value === ")") {
      const start = stack.pop();
      const expected = token.value === "}" ? "{" : token.value === "]" ? "[" : "(";
      if (!start || start.value !== expected) {
        return MISSING_ISSUE_TEXT;
      }
      pairs.set(start.index, i);
    }
  }
  if (stack.length > 0) {
    return MISSING_ISSUE_TEXT;
  }

  const isPunctuation = (index, value) =>
    tokens[index]?.type === "punctuation" && tokens[index].value === value;
  const isIdentifier = (index, value) =>
    tokens[index]?.type === "identifier" && tokens[index].value === value;

  // Split only at the current nesting level; string values never act as delimiters.
  const splitMembers = (start, end) => {
    const members = [];
    let memberStart = start;
    for (let i = start; i < end; i++) {
      if (pairs.has(i)) {
        i = pairs.get(i);
      } else if (isPunctuation(i, ",")) {
        if (memberStart < i) {
          members.push([memberStart, i]);
        }
        memberStart = i + 1;
      }
    }
    if (memberStart < end) {
      members.push([memberStart, end]);
    }
    return members;
  };

  const objectProperties = (start, end) => {
    if (!isPunctuation(start, "{") || pairs.get(start) !== end - 1) {
      return undefined;
    }
    const properties = new Map();
    for (const [first, last] of splitMembers(start + 1, end - 1)) {
      const key = tokens[first];
      if ((key.type !== "identifier" && key.type !== "string") || !isPunctuation(first + 1, ":")) {
        // Spread, computed and shorthand properties can override known properties.
        return undefined;
      }
      const values = properties.get(key.value) ?? [];
      values.push([first + 2, last]);
      properties.set(key.value, values);
    }
    return properties;
  };

  const literalProperty = (properties, name) => {
    const values = properties.get(name) ?? [];
    if (values.length !== 1) {
      return undefined;
    }
    const [start, end] = values[0];
    return end === start + 1 && tokens[start]?.type === "string"
      ? tokens[start].value
      : undefined;
  };

  const issueDescriptions = [];
  let ambiguous = false;
  const collectAnnotation = (start, end, allowArray = false) => {
    if (allowArray && isPunctuation(start, "[") && pairs.get(start) === end - 1) {
      for (const [first, last] of splitMembers(start + 1, end - 1)) {
        collectAnnotation(first, last);
      }
      return;
    }
    const properties = objectProperties(start, end);
    if (!properties) {
      ambiguous = true;
      return;
    }
    const type = literalProperty(properties, "type");
    if (type === undefined) {
      ambiguous = true;
    } else if (type === "issue") {
      const description = literalProperty(properties, "description");
      if (description === undefined) {
        ambiguous = true;
      } else {
        issueDescriptions.push(description);
      }
    }
  };

  // The optional second argument is the test details object, containing `annotation`.
  let callOpen = 1;
  if (isPunctuation(callOpen, ".") && tokens[callOpen + 1]?.type === "identifier") {
    callOpen += 2;
  }
  if (!(isIdentifier(0, "test") || isIdentifier(0, "it")) || !isPunctuation(callOpen, "(")
    || pairs.get(callOpen) !== tokens.length - 1) {
    return MISSING_ISSUE_TEXT;
  }
  const args = splitMembers(callOpen + 1, tokens.length - 1);
  if (args.length >= 2 && isPunctuation(args[1][0], "{")) {
    const details = objectProperties(...args[1]);
    if (!details) {
      ambiguous = true;
    } else {
      const annotations = details.get("annotation") ?? [];
      if (annotations.length > 1) {
        ambiguous = true;
      } else if (annotations.length === 1) {
        collectAnnotation(...annotations[0], true);
      }
    }
  }

  // Dynamic annotations are supported only in explicit test.info().annotations.push calls.
  for (let i = callOpen + 1; i < tokens.length; i++) {
    if (isPunctuation(i - 1, ".") || !isIdentifier(i, "test")
      || !isPunctuation(i + 1, ".") || !isIdentifier(i + 2, "info")
      || !isPunctuation(i + 3, "(") || !isPunctuation(i + 4, ")")
      || !isPunctuation(i + 5, ".") || !isIdentifier(i + 6, "annotations")
      || !isPunctuation(i + 7, ".") || !isIdentifier(i + 8, "push")
      || !isPunctuation(i + 9, "(")) {
      continue;
    }
    const end = pairs.get(i + 9);
    if (end === undefined) {
      return MISSING_ISSUE_TEXT;
    }
    for (const [first, last] of splitMembers(i + 10, end)) {
      collectAnnotation(first, last);
    }
    i = end;
  }

  return !ambiguous && issueDescriptions.length === 1
    ? normalizeIssueDescription(issueDescriptions[0])
    : MISSING_ISSUE_TEXT;
}

/**
 * Extracts the issue description of the test declared at the given location.
 * Never searches outside that test, so another test's annotation is never reported.
 * @param {string} sourceContent Full source file content.
 * @param {number} line 1-based line number of the test declaration.
 * @param {number} [column] 1-based column of the test declaration.
 * @returns {string} Issue description if present, otherwise fallback text.
 */
function extractExpectedIssueFromSource(sourceContent, line, column) {
  const testSource = extractTestSourceAt(sourceContent, line, column);
  return testSource ? extractIssueFromTestSource(testSource) : MISSING_ISSUE_TEXT;
}

/**
 * Extracts the 1-based line and optional column from a test location.
 * @param {string} location Location value from error-context Test info.
 * @returns {{ line: number, column?: number } | undefined} Position, or undefined when absent.
 */
function extractPositionFromLocation(location) {
  const positionMatch = location.match(/:(\d+)(?::(\d+))?$/);
  if (!positionMatch) {
    return undefined;
  }
  const line = Number(positionMatch[1]);
  return positionMatch[2] === undefined ? { line } : { line, column: Number(positionMatch[2]) };
}

/**
 * Strips trailing line/column numbers from a test location.
 * @param {string} location Location value from error-context Test info.
 * @returns {string} Source path without trailing :line or :line:column suffix.
 */
function extractSourcePathFromLocation(location) {
  return location.replace(/:\d+(?::\d+)?$/, "");
}

/**
 * Resolves a source file only when it is a bounded regular file inside an allowed source root.
 * realpath checks prevent symlinks from escaping roots; stat excludes devices such as /dev/zero.
 * @param {string} candidate Candidate absolute path.
 * @returns {string | undefined} Safe real path, or undefined.
 */
function resolveSafeSourcePath(candidate) {
  let realCandidate;
  let sourceStat;
  try {
    realCandidate = realpathSync(candidate);
    sourceStat = statSync(realCandidate);
  } catch {
    return undefined;
  }
  if (!sourceStat.isFile() || sourceStat.size > MAX_SOURCE_FILE_BYTES) {
    return undefined;
  }

  const allowedRoots = [repoRoot, workspaceRepoRoot];
  for (const root of allowedRoots) {
    let realRoot;
    try {
      realRoot = realpathSync(root);
    } catch {
      continue;
    }
    const pathFromRoot = relative(root, candidate);
    if (pathFromRoot !== ".." && !pathFromRoot.startsWith(`..${sep}`)
      && !isAbsolute(pathFromRoot) && resolve(realRoot, pathFromRoot) === realCandidate) {
      return realCandidate;
    }
  }
  return undefined;
}

/**
 * Resolves test source file path from failure output folder and reported location.
 * First checks package-local path before falling back to workspace module layout. Candidates
 * must resolve to bounded regular files inside the analysis directory or configured workspace.
 * @param {string} folderPath Absolute failure output folder path.
 * @param {string} location Location value from error-context Test info.
 * @param {string} [reportedRootDir] Playwright config.rootDir from the reporting machine.
 * @returns {string | undefined} Resolved absolute source file path when derivable.
 */
function resolveSourceFilePath(folderPath, location, reportedRootDir) {
  const normalizedFolderPath = folderPath.replaceAll("\\", "/");
  const tokenIndex = normalizedFolderPath.indexOf("/playwright-report/");
  if (tokenIndex < 0) {
    return undefined;
  }

  const packageRoot = normalizedFolderPath.slice(0, tokenIndex);
  const sourcePath = extractSourcePathFromLocation(location);
  if (!sourcePath) {
    return undefined;
  }

  const reportedPaths = [];
  if (reportedRootDir && !isAbsolute(sourcePath) && !win32.isAbsolute(sourcePath)) {
    if (win32.isAbsolute(reportedRootDir) && !isAbsolute(reportedRootDir)) {
      reportedPaths.push(win32.resolve(reportedRootDir, sourcePath));
    } else if (isAbsolute(reportedRootDir)) {
      reportedPaths.push(resolve(reportedRootDir, sourcePath));
    }
  }
  reportedPaths.push(sourcePath);
  for (const reportedPath of reportedPaths) {
    const safePackageSource = resolveSafeSourcePath(resolve(packageRoot, reportedPath));
    if (safePackageSource) {
      return safePackageSource;
    }

    // Absolute paths may refer to the test runner; match their longest suffix inside the package.
    if (isAbsolute(reportedPath) || win32.isAbsolute(reportedPath)) {
      const parts = reportedPath.split(/[\\/]+/u).filter(Boolean);
      if (!parts.includes("..")) {
        for (let start = 0; start <= parts.length - 2; start++) {
          const safeSource = resolveSafeSourcePath(resolve(packageRoot, ...parts.slice(start)));
          if (safeSource) {
            return safeSource;
          }
        }
      }
    }
  }

  const packageNameMatch = normalizedFolderPath.match(
    /\/(@pentaho-apps\/[^/]+)\/playwright-report\//
  );
  if (!packageNameMatch) {
    return undefined;
  }

  const packageName = packageNameMatch[1];
  const moduleName = packageName
    .replace("@pentaho-apps/pentaho-app-shell-", "")
    .replace(/-automation$/, "");

  for (const root of [workspaceRepoRoot, repoRoot]) {
    const sourceFromWorkspace = resolve(root, moduleName, "automation", sourcePath);
    const safeSource = resolveSafeSourcePath(sourceFromWorkspace);
    if (safeSource) {
      return safeSource;
    }
  }
  return undefined;
}

/**
 * Extracts expected issue from the referenced source file at the reported test location.
 * Embedded source snippets are ignored because they may include neighboring test declarations.
 * @param {string} errorContextContent Full error-context file content.
 * @param {string} folderPath Absolute failure output folder path.
 * @param {string} [location] Location value from error-context Test info.
 * @param {string} [reportedRootDir] Playwright config.rootDir from the reporting machine.
 * @returns {string} Extracted issue description or fallback text.
 */
function extractExpectedIssueWithFallback(
  errorContextContent,
  folderPath,
  location = extractTestInfo(errorContextContent).location,
  reportedRootDir
) {
  const sourceFilePath = resolveSourceFilePath(folderPath, location, reportedRootDir);
  if (!sourceFilePath) {
    return MISSING_ISSUE_TEXT;
  }

  const position = extractPositionFromLocation(location);
  if (position === undefined) {
    return MISSING_ISSUE_TEXT;
  }

  const sourceContent = readFileSync(sourceFilePath, "utf8");
  return extractExpectedIssueFromSource(sourceContent, position.line, position.column);
}

/**
 * Returns the description of the first "issue" annotation.
 * @param {{ type?: string, description?: string }[]} annotations Test annotations.
 * @returns {string | undefined} Normalized issue description.
 */
function issueFromAnnotations(annotations) {
  const issue = annotations.find(annotation =>
    annotation?.type === "issue" && typeof annotation.description === "string" && annotation.description.trim());
  return issue ? issue.description.replace(/\s+/g, " ").trim() : undefined;
}

/**
 * Collects expected failures classified by Playwright.
 * @param {string[]} candidateFolders Absolute folders matched by the report output patterns.
 * @returns {ExpectedFailure[]} Expected failures with their issue descriptions.
 */
function collectExpectedFailures(candidateFolders) {
  return selectTests(repoRoot, "expected", candidateFolders).map(test => {
    let expectedIssue = issueFromAnnotations(test.annotations) ?? MISSING_ISSUE_TEXT;
    if (expectedIssue === MISSING_ISSUE_TEXT) {
      expectedIssue = extractExpectedIssueWithFallback(
        "",
        test.reportPath,
        test.location,
        test.reportedRootDir
      );
    }
    return { name: test.name, location: test.location, expectedIssue };
  });
}

/**
 * Renders expected failures as markdown table content.
 * @param {ExpectedFailure[]} expectedFailures Failures to render.
 * @returns {string} Markdown content for expected-failures.md.
 */
function buildExpectedFailuresMarkdown(expectedFailures) {
  const lines = [
    "",
    `Total Expected Failures: ${expectedFailures.length}`,
    "",
    "| Name | Location | Expected Issue |",
    "| --- | --- | --- |",
    ...expectedFailures.map(
      failure =>
        `| ${markdownEscape(failure.name)} | ${markdownEscape(failure.location)} | ${markdownEscape(failure.expectedIssue)} |`
    )
  ];

  return `${lines.join("\n")}\n`;
}

/**
 * Generates expected-failures.md in repo root, or removes it when no matches exist.
 * @returns {Promise<void>}
 */
async function main() {
  const candidateFolders = await getCandidateFolders(reportOutputPath, repoRoot);
  const expectedFailures = collectExpectedFailures(candidateFolders);

  if (expectedFailures.length === 0) {
    if (existsSync(expectedFailuresFile)) {
      rmSync(expectedFailuresFile);
    }

    console.log("No expected failures found.");
  } else {
    const expectedFailuresMd = buildExpectedFailuresMarkdown(expectedFailures);
    writeFileSync(expectedFailuresFile, expectedFailuresMd, "utf8");
    console.log(
      `Generated ${toPosixRelativePath(expectedFailuresFile, repoRoot)}.`
    );
  }
}

// Run only when invoked as script, not when imported for tests or reuse.
if (require.main === module) {
  main().catch(error => {
    console.error(error);
    process.exitCode = 1;
  });
}

module.exports = { MISSING_ISSUE_TEXT, issueFromAnnotations, extractExpectedIssueFromSource, extractPositionFromLocation, extractTestSourceAt, extractSourcePathFromLocation, resolveSourceFilePath, resolveSafeSourcePath, extractExpectedIssueWithFallback };
