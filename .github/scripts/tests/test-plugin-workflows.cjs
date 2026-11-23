"use strict";

// Exercise shared workflow scripts without a registry or Docker daemon.

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { afterEach, beforeEach, describe, test } = require("node:test");

const TESTS_DIR = __dirname;
const ROOT = path.resolve(TESTS_DIR, "../../..");
const ACTIONS = path.join(ROOT, ".github/actions");
const SQL_FILES = [
  "create_jcr_postgresql.sql",
  "create_quartz_postgresql.sql",
  "create_repository_postgresql.sql",
  "pentaho_logging_postgresql.sql",
  "pentaho_mart_postgresql.sql",
];
const SKIPPED_SQL_FILES = [
  "migrate_repository.sql",
  "alter_script_postgresql_BISERVER-13674.sql",
  "pentaho_mart_drop_postgresql.sql",
];
const SERVER_IMAGE_DIGEST = "registry.example/server@sha256:" + "a".repeat(64);

// Fake docker/mvn/npm/npx executable. Logs every call to STUB_LOG and simulates the tools the scripts use.
function stubMain() {
  const fs = require("node:fs");
  const path = require("node:path");

  const tool = path.basename(process.argv[1]);
  const args = process.argv.slice(2);
  const env = process.env;
  fs.appendFileSync(env.STUB_LOG, JSON.stringify({
    tool,
    args,
    version: env.MANUAL_BUILD_NUMBER ?? null,
    project: env.PLAYWRIGHT_PROJECT ?? null,
    context: env.MANUAL_SERVER_CONTEXT ?? null,
    env_file: env.PT_ENV_FILE ?? null,
    results_dir: env.PT_RESULTS_DIR ?? null,
  }) + "\n");
  if ([tool, ...args.slice(0, 1)].join(" ") === env.FAIL_COMMAND) {
    console.error("stub command failed");
    process.exit(7);
  }
  if (tool === "docker") {
    if (args[0] === "image" && args[1] === "inspect") {
      console.log(env.IMAGE_REPO_DIGEST);
    } else if (args[0] === "create") {
      console.log("sql-container");
    } else if (args[0] === "cp") {
      fs.cpSync(env.SQL_FIXTURE, args[2], { recursive: true });
    } else if (args[0] === "logs") {
      console.log("service console output");
    }
  } else if (tool === "mvn" && !(args.length === 1 && args[0] === "--version") && !env.MVN_NO_STAGE) {
    const plugin = path.join(env.GITHUB_WORKSPACE, "pentaho-build/pentaho-solutions/system/example");
    fs.mkdirSync(plugin, { recursive: true });
    fs.writeFileSync(path.join(plugin, "plugin.xml"), "<plugin/>");
  } else {
    console.log(tool + " command output");
  }
}
const STUB = "#!" + process.execPath + "\n(" + stubMain.toString() + ")();\n";

function isDirectory(target) {
  try {
    return fs.statSync(target).isDirectory();
  } catch {
    return false;
  }
}

function indexOf(text, needle) {
  const index = text.indexOf(needle);
  assert.notEqual(index, -1, `Missing: ${needle}`);
  return index;
}

function hasItem(collection, item) {
  if (typeof collection === "string") {
    return collection.includes(item);
  }
  return collection.some(entry => JSON.stringify(entry) === JSON.stringify(item));
}

function assertIn(item, collection, message) {
  assert.ok(hasItem(collection, item), message ?? `Missing: ${JSON.stringify(item)}`);
}

function assertNotIn(item, collection, message) {
  assert.ok(!hasItem(collection, item), message ?? `Unexpected: ${JSON.stringify(item)}`);
}

function assertLess(actual, expected) {
  assert.ok(actual < expected, `${actual} is not less than ${expected}`);
}

function sortedNames(names) {
  return [...names].sort();
}

function pick(object, keys) {
  return Object.fromEntries(keys.map(key => [key, object[key]]));
}

function splitOnce(line, separator) {
  const index = line.indexOf(separator);
  assert.notEqual(index, -1, `Malformed output line: ${line}`);
  return [line.slice(0, index), line.slice(index + separator.length)];
}

function useWorkflowSed(workspace) {
  if (process.platform === "darwin") {
    // The workflow uses GNU sed; adapt its in-place flag for local macOS runs.
    fs.writeFileSync(path.join(workspace.bin, "sed"),
      '#!/bin/bash\nshift\nexec /usr/bin/sed -i "" "$@"\n', { mode: 0o755 });
  }
}

class Workspace {
  constructor() {
    // Fixture dirs live inside the tests folder, not the system temp dir.
    this.base = fs.realpathSync(fs.mkdtempSync(path.join(TESTS_DIR, ".workspace-")));
    this.bin = path.join(this.base, "bin");
    fs.mkdirSync(this.bin);
    for (const tool of ["docker", "mvn", "npm", "npx"]) {
      const executable = path.join(this.bin, tool);
      fs.writeFileSync(executable, STUB);
      fs.chmodSync(executable, 0o755);
    }
    this.sql = path.join(this.base, "sql-image");
    fs.mkdirSync(this.sql);
    for (const name of [...SQL_FILES, ...SKIPPED_SQL_FILES]) {
      fs.writeFileSync(path.join(this.sql, name), "-- image SQL\n");
    }
    this.output = path.join(this.base, "output");
    this.summary = path.join(this.base, "summary");
    this.log = path.join(this.base, "commands.jsonl");
    this.env = {
      ...process.env,
      PATH: `${this.bin}${path.delimiter}${process.env.PATH}`,
      STUB_LOG: this.log,
      SQL_FIXTURE: this.sql,
      IMAGE_REPO_DIGEST: SERVER_IMAGE_DIGEST,
      GITHUB_WORKSPACE: this.base,
      GITHUB_OUTPUT: this.output,
      GITHUB_STEP_SUMMARY: this.summary,
      VERBOSE: "false",
    };
  }

  dispose() {
    fs.rmSync(this.base, { recursive: true, force: true });
  }

  runScript(relative, { success = true, ...env } = {}) {
    const script = path.join(ACTIONS, relative);
    const runner = path.extname(script) === ".cjs" ? process.execPath : "bash";
    const result = spawnSync(runner, [script], {
      cwd: this.base,
      env: { ...this.env, ...env },
      encoding: "utf8",
    });
    const text = result.stdout + result.stderr;
    if (success) {
      assert.equal(result.status, 0, text);
    } else {
      assert.notEqual(result.status, 0, text);
    }
    return text;
  }

  outputs() {
    const values = {};
    const lines = fs.readFileSync(this.output, "utf8").split(/\r?\n/);
    if (lines.at(-1) === "") {
      lines.pop();
    }
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.includes("<<")) {
        const [key, delimiter] = splitOnce(line, "<<");
        const content = [];
        let terminated = false;
        for (i += 1; i < lines.length; i++) {
          if (lines[i] === delimiter) {
            terminated = true;
            break;
          }
          content.push(lines[i]);
        }
        assert.ok(terminated, `Unterminated output: ${key}`);
        values[key] = content.join("\n");
      } else {
        const [key, value] = splitOnce(line, "=");
        values[key] = value;
      }
    }
    return values;
  }

  commands(tool) {
    return fs.readFileSync(this.log, "utf8")
      .split("\n")
      .filter(line => line.trim() !== "")
      .map(line => JSON.parse(line))
      .filter(entry => entry.tool === tool);
  }

  extract({ image = "registry.example/server:11", ...env } = {}) {
    return this.runScript("pentaho-server-fixtures/extract-sql.sh", {
      SERVER_IMAGE: image,
      SQL_OUTPUT_DIR: path.join(this.base, "extracted"),
      PLUGIN_PATH: "/opt/server/pentaho-solutions/system/",
      ...env,
    });
  }

  stage(env = {}) {
    return this.runScript("pentaho-server-fixtures/stage-fixtures.sh", {
      VOLUME_DIR: path.join(this.base, "volume"),
      HOST_VOLUME_PATH: "/cache/owner/repo/123",
      SQL_SOURCE_DIR: this.sql,
      ...env,
    });
  }

  plugin(name) {
    const plugin = path.join(this.base, "volume/pentaho-solutions/system", name);
    fs.mkdirSync(plugin, { recursive: true });
    fs.writeFileSync(path.join(plugin, "plugin.xml"), "<plugin/>");
    return plugin;
  }

  report(tests) {
    const folder = path.join(this.base, "playwright-report/chrome");
    fs.mkdirSync(folder, { recursive: true });
    fs.writeFileSync(path.join(folder, "ctrf-report.json"), JSON.stringify({
      results: { summary: { tests: 99, failed: 99 }, tests },
    }));
  }

  version(value = "11.0.0.4.338") {
    const folder = path.join(this.base, "src/resources/.auth");
    fs.mkdirSync(folder, { recursive: true });
    fs.writeFileSync(path.join(folder, "server-version.json"), JSON.stringify({ version: value }));
  }

  pullRequestNotification(env = {}) {
    this.runScript("notify-slack/payload.sh", {
      SLACK_CHANNEL: "ci",
      WORKFLOW_NAME: "PR Workflow",
      FORMAT: "pull_request",
      PR_NUMBER: "42",
      PR_URL: "https://github.com/owner/repo/pull/42",
      BRANCH: "feature",
      EVENT_NAME: "pull_request",
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_REPOSITORY: "owner/repo",
      GITHUB_RUN_ID: "123",
      GITHUB_ACTOR: "tester",
      ...env,
    });
    const outputs = this.outputs();
    return [outputs.title, JSON.parse(outputs.json)];
  }

  checkReports(pattern) {
    fs.rmSync(this.output, { force: true });
    const text = this.runScript("playwright-test-summary/check-reports.cjs", {
      SEARCH_DIRECTORY: this.base,
      REPORT_PATH: pattern,
      GITHUB_ACTION_PATH: path.join(ACTIONS, "playwright-test-summary"),
    });
    return [this.outputs().found, text];
  }
}

// Runs a case inline. node:test's t.test() would also run the describe-level beforeEach/afterEach
// hooks per case, swapping the Workspace mid-test, so cases must not use it.
function subtest(name, run) {
  try {
    run();
  } catch (error) {
    error.message = `${name}: ${error.message}`;
    throw error;
  }
}

function walkFiles(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkFiles(full));
    } else if (entry.isFile()) {
      files.push(full);
    }
  }
  return files.sort();
}

describe("WorkflowScripts", () => {
  let w;

  beforeEach(() => {
    w = new Workspace();
  });

  afterEach(() => {
    w.dispose();
  });

  test("test_sql_from_server_home_excludes_migrations", () => {
    w.extract({ REGISTRY_USERNAME: "user", REGISTRY_PASSWORD: "not-a-real-secret" });
    assert.deepEqual(sortedNames(fs.readdirSync(path.join(w.base, "extracted"))), sortedNames(SQL_FILES));
    const cp = w.commands("docker").filter(c => c.args[0] === "cp")[0];
    assert.equal(cp.args[1], "sql-container:/opt/server/data/postgresql/.");
    assertIn(["rm", "--force", "sql-container"], w.commands("docker").map(c => c.args));
    assert.ok(!fs.readFileSync(w.log, "utf8").includes("not-a-real-secret"));
  });

  test("test_sql_verbose_is_opt_in", () => {
    assert.ok(!w.extract().includes(SQL_FILES[0]));
    assert.ok(w.extract({ VERBOSE: "true" }).includes(SQL_FILES[0]));
  });

  test("test_sql_extraction_and_output_use_immutable_image", async t => {
    for (const image of ["registry.example/server", "registry.example/server:11", SERVER_IMAGE_DIGEST]) {
      subtest(`image=${image}`, () => {
        w.extract({ image });
        const commands = w.commands("docker").map(c => c.args);
        assertIn(["pull", "--quiet", image], commands);
        assert.deepEqual(commands.filter(c => c[0] === "create").at(-1), ["create", SERVER_IMAGE_DIGEST]);
        assert.equal(w.outputs().server_image, SERVER_IMAGE_DIGEST);
      });
    }
  });

  test("test_unavailable_image_digest_stops_before_extraction", () => {
    const text = w.extract({ success: false, FAIL_COMMAND: "docker image" });
    assert.ok(text.includes("::error::"));
    assertNotIn("create", w.commands("docker").map(c => c.args[0]));
    assert.ok(!fs.existsSync(w.output));
  });

  test("test_missing_or_invalid_image_digest_is_rejected", async t => {
    for (const digest of ["", "<no value>", "registry.example/server:latest",
      "sha256:" + "a".repeat(64), "registry.example/server@sha256:abc"]) {
      subtest(`digest=${digest}`, () => {
        assert.ok(w.extract({ success: false, IMAGE_REPO_DIGEST: digest }).includes("::error::"));
        assertNotIn("create", w.commands("docker").map(c => c.args[0]));
        assert.ok(!fs.existsSync(w.output));
      });
    }
  });

  test("test_image_digest_matches_requested_repository", () => {
    const other = "mirror.example/server@sha256:" + "b".repeat(64);
    w.extract({ IMAGE_REPO_DIGEST: `${other}\n${SERVER_IMAGE_DIGEST}` });
    assert.equal(w.outputs().server_image, SERVER_IMAGE_DIGEST);
    assertIn(["create", SERVER_IMAGE_DIGEST], w.commands("docker").map(c => c.args));
  });

  test("test_explicit_image_digest_is_preserved", () => {
    const explicit = "registry.example/server:11@sha256:" + "c".repeat(64);
    w.extract({ image: explicit, IMAGE_REPO_DIGEST: "mirror.example/server@sha256:" + "b".repeat(64) });
    assert.equal(w.outputs().server_image, explicit);
    assertNotIn(["image", "inspect"], w.commands("docker").map(c => c.args.slice(0, 2)));
  });

  test("test_invalid_explicit_image_digest_is_rejected", () => {
    assert.ok(w.extract({ success: false, image: "registry.example/server@sha256:abc" }).includes("::error::"));
    assertNotIn("create", w.commands("docker").map(c => c.args[0]));
  });

  test("test_docker_hub_aliases_match_short_digest", async t => {
    const hub = "pentaho/server@sha256:" + "d".repeat(64);
    for (const image of ["pentaho/server:11", "docker.io/pentaho/server:11", "index.docker.io/pentaho/server"]) {
      subtest(`image=${image}`, () => {
        w.extract({ image, IMAGE_REPO_DIGEST: hub });
        assert.equal(w.outputs().server_image, hub);
      });
    }
  });

  test("test_image_digest_from_other_repository_is_rejected", () => {
    const text = w.extract({ success: false, IMAGE_REPO_DIGEST: "mirror.example/server@sha256:" + "b".repeat(64) });
    assert.ok(text.includes("::error::"));
    assertNotIn("create", w.commands("docker").map(c => c.args[0]));
  });

  test("test_fixtures_pass_resolved_image_to_service", () => {
    const action = fs.readFileSync(path.join(ACTIONS, "pentaho-server-fixtures/action.yml"), "utf8");
    const workflow = fs.readFileSync(path.join(ROOT, ".github/workflows/integration-tests-npm.yml"), "utf8");
    assert.ok(action.includes("value: ${{ steps.sql.outputs.server_image }}"));
    assert.ok(workflow.includes("server_image: ${{ steps.fixtures.outputs.server_image }}"));
    assert.ok(workflow.includes("image: ${{ needs.setup.outputs.server_image }}"));
  });

  test("test_startup_logs_are_preserved_by_cleanup_before_emptying_volume", () => {
    const workflow = fs.readFileSync(path.join(ROOT, ".github/workflows/integration-tests-npm.yml"), "utf8");
    const cleanup = workflow.slice(indexOf(workflow, "\n  cleanup:"));
    const setup = workflow.slice(indexOf(workflow, "\n  setup:"), indexOf(workflow, "\n  tests:"));
    assert.ok(!setup.includes("startup-server-logs"));
    const preserve = indexOf(cleanup, "-startup-server-logs");
    assert.ok(cleanup.slice(0, preserve).includes("if: ${{ needs.tests.result == 'failure' }}"));
    assertLess(preserve, indexOf(cleanup, "name: Empty volume"));
  });

  test("test_missing_sql_fails_and_removes_container", () => {
    fs.rmSync(path.join(w.sql, SQL_FILES[0]));
    assert.ok(w.extract({ success: false }).includes("::error::"));
    assertIn(["rm", "--force", "sql-container"], w.commands("docker").map(c => c.args));
  });

  test("test_missing_optional_sql_is_skipped", () => {
    fs.rmSync(path.join(w.sql, "pentaho_mart_postgresql.sql"));
    w.extract();
    assert.deepEqual(
      sortedNames(fs.readdirSync(path.join(w.base, "extracted"))),
      sortedNames(SQL_FILES.filter(name => name !== "pentaho_mart_postgresql.sql")),
    );
  });

  test("test_failed_sql_copy_does_not_succeed", () => {
    assert.ok(w.extract({ success: false, FAIL_COMMAND: "docker cp" }).includes("not found"));
  });

  test("test_failed_registry_login_stops_before_pull", () => {
    w.extract({
      success: false,
      REGISTRY_USERNAME: "user",
      REGISTRY_PASSWORD: "test-token",
      FAIL_COMMAND: "docker login",
    });
    assertNotIn("pull", w.commands("docker").map(c => c.args[0]));
  });

  test("test_unqualified_images_do_not_trigger_registry_login", async t => {
    for (const image of ["pentaho-server", "pentaho-server:11", "pentaho.server",
      "pentaho-server@sha256:" + "a".repeat(64), "pentaho/pentaho-server:11"]) {
      subtest(`image=${image}`, () => {
        w.extract({
          image,
          REGISTRY_USERNAME: "user",
          REGISTRY_PASSWORD: "test-token",
          IMAGE_REPO_DIGEST: image.split("@")[0].split(":")[0] + "@sha256:" + "a".repeat(64),
          FAIL_COMMAND: "docker login",
        });
        const commands = w.commands("docker").map(c => c.args);
        assertNotIn("login", commands.map(c => c[0]));
        assertIn(["pull", "--quiet", image], commands);
      });
    }
  });

  test("test_qualified_images_log_in_to_registry_host", async t => {
    for (const registry of ["registry.example", "registry.example:5000", "localhost",
      "localhost:5000", "registry:5000"]) {
      subtest(`registry=${registry}`, () => {
        w.extract({
          image: `${registry}/pentaho-server:11`,
          IMAGE_REPO_DIGEST: `${registry}/pentaho-server@sha256:` + "a".repeat(64),
          REGISTRY_USERNAME: "user",
          REGISTRY_PASSWORD: "test-token",
        });
        const logins = w.commands("docker").map(c => c.args).filter(args => args[0] === "login");
        assert.deepEqual(logins.at(-1), ["login", registry, "--username", "user", "--password-stdin"]);
        assert.ok(!fs.readFileSync(w.log, "utf8").includes("test-token"));
      });
    }
  });

  test("test_plugin_mounts_match_scheduler_bind_mount_style", () => {
    w.plugin("pas-scheduler");
    w.plugin("scheduler-plugin");
    w.stage({
      REQUIRED_PLUGINS: "pas-scheduler,scheduler-plugin",
      PLUGIN_PATH: "/opt/server/pentaho-solutions/system/",
    });
    const output = w.outputs();
    assert.equal(output.plugins, "pas-scheduler,scheduler-plugin");
    assert.equal(output.mounts.split("--mount").length - 1, 3);
    assert.ok(output.mounts.includes("target=/opt/server/tomcat/logs"));
    assert.ok(output.mounts.includes("target=/opt/server/pentaho-solutions/system/scheduler-plugin"));
  });

  test("test_no_plugins_uses_bundled_plugins", () => {
    assert.ok(w.stage().includes("::warning::"));
    assert.equal(w.outputs().mounts.split("--mount").length - 1, 1);
  });

  test("test_missing_required_plugin_fails", () => {
    assert.ok(w.stage({ success: false, REQUIRED_PLUGINS: "missing" }).includes("Required plugin"));
  });

  test("test_any_staged_plugin_needs_descriptor", () => {
    const plugin = w.plugin("broken");
    fs.rmSync(path.join(plugin, "plugin.xml"));
    assert.ok(w.stage({ success: false }).includes("missing plugin.xml"));
  });

  test("test_invalid_plugin_name_fails", () => {
    w.plugin("bad,name");
    assert.ok(w.stage({ success: false }).includes("Invalid plugin"));
  });

  test("test_maven_flags_and_multiline_directives", async t => {
    for (const tests of ["true", "false"]) {
      subtest(`tests=${tests}`, () => {
        w.runScript("build-plugins/build.sh", {
          MAVEN_SETTINGS_FILE: "/settings file.xml",
          RUN_UNIT_TESTS: tests,
          MVN_DIRECTIVES: "-f app/pom.xml\n-pl assemblies/plugin -am",
        });
        const args = w.commands("mvn").at(-1).args;
        assertIn("/settings file.xml", args);
        assert.deepEqual(args.slice(-5), ["-f", "app/pom.xml", "-pl", "assemblies/plugin", "-am"]);
        assertIn(tests === "true" ? "-DskipTests=false" : "-DskipTests", args);
        if (tests === "true") {
          assertIn("-Dmaven.test.failure.ignore=false", args);
        } else {
          assertNotIn("-Dmaven.test.failure.ignore=false", args);
        }
        assertNotIn("-Dmaven-surefire-plugin.testFailureIgnore=false", args);
        assertIn(`-DbiserverHome=${w.base}/pentaho-build`, args);
      });
    }
  });

  test("test_build_failure_propagates", () => {
    w.runScript("build-plugins/build.sh", {
      success: false,
      MAVEN_SETTINGS_FILE: "/settings.xml",
      FAIL_COMMAND: "mvn -B",
    });
  });

  test("test_maven_quoted_arguments_are_not_shell_evaluated", () => {
    w.runScript("build-plugins/build.sh", {
      MAVEN_SETTINGS_FILE: "/settings.xml",
      MVN_DIRECTIVES: '-Dlabel="hello world" -Dliteral=$HOME',
    });
    const args = w.commands("mvn").at(-1).args;
    assertIn("-Dlabel=hello world", args);
    assertIn("-Dliteral=$HOME", args);
  });

  test("test_maven_invalid_quoting_fails_before_build", () => {
    w.runScript("build-plugins/build.sh", {
      success: false,
      MAVEN_SETTINGS_FILE: "/settings.xml",
      MVN_DIRECTIVES: '-Dlabel="unterminated',
    });
    assert.ok(!fs.existsSync(w.log));
  });

  test("test_build_verbose_is_opt_in", () => {
    w.runScript("build-plugins/build.sh", { MAVEN_SETTINGS_FILE: "/settings.xml" });
    assertNotIn(["--version"], w.commands("mvn").map(c => c.args));
    const text = w.runScript("build-plugins/build.sh", { MAVEN_SETTINGS_FILE: "/settings.xml", VERBOSE: "true" });
    assert.ok(text.includes("plugin.xml"));
    assertIn(["--version"], w.commands("mvn").map(c => c.args));
  });

  test("test_verbose_build_without_staging_leaves_it_to_post_build", () => {
    const text = w.runScript("build-plugins/build.sh", {
      MAVEN_SETTINGS_FILE: "/settings.xml",
      VERBOSE: "true",
      MVN_NO_STAGE: "1",
    });
    assert.ok(text.includes("No plugins staged by Maven"));
    assert.ok(!fs.existsSync(path.join(w.base, "pentaho-build")));
  });

  test("test_install_matches_scheduler_and_browser_selection", () => {
    w.runScript("install-playwright/install.sh", { PLAYWRIGHT_BROWSERS: "chromium firefox webkit chrome msedge" });
    assert.deepEqual(w.commands("npm")[0].args, ["install"]);
    assert.deepEqual(w.commands("npx")[0].args,
      ["playwright", "install", "--with-deps", "chromium", "firefox", "webkit", "chrome", "msedge"]);
  });

  test("test_empty_browsers_skips_install", () => {
    w.runScript("install-playwright/install.sh", { PLAYWRIGHT_BROWSERS: "" });
    assert.equal(w.commands("npx").length, 0);
  });

  test("test_install_failure_propagates", () => {
    w.runScript("install-playwright/install.sh", { success: false, FAIL_COMMAND: "npm install" });
    assert.equal(w.commands("npx").length, 0);
  });

  test("test_test_args_and_failure_propagation", () => {
    w.runScript("run-playwright/run.sh", { TEST_SCRIPT: "test", TEST_ARGS: "--project=chrome --workers=1" });
    assert.deepEqual(w.commands("npm").at(-1).args, ["run", "test", "--", "--project=chrome", "--workers=1"]);
    w.runScript("run-playwright/run.sh", { success: false, TEST_SCRIPT: "test", FAIL_COMMAND: "npm run" });
  });

  test("test_multiline_test_args_are_all_passed", () => {
    w.runScript("run-playwright/run.sh", {
      TEST_SCRIPT: "test",
      TEST_ARGS: "--project=chrome\n--workers=1\r\n  --retries=2\n",
    });
    assert.deepEqual(w.commands("npm").at(-1).args,
      ["run", "test", "--", "--project=chrome", "--workers=1", "--retries=2"]);
    w.runScript("run-playwright/run.sh", { TEST_SCRIPT: "test", TEST_ARGS: "\n\n" });
    assert.deepEqual(w.commands("npm").at(-1).args, ["run", "test"]);
  });

  test("test_installation_has_a_separate_timeout_without_duplicate_install", () => {
    const workflow = fs.readFileSync(path.join(ROOT, ".github/workflows/integration-tests-npm.yml"), "utf8");
    assert.ok(workflow.includes("timeout-minutes: ${{ inputs.playwright_install_timeout_minutes }}"));
    assert.match(workflow,
      /playwright_install_timeout_minutes:\s+type: number\s+required: false\s+default: 10/);
    assert.ok(workflow.includes("install_dependencies: false"));
    assertLess(indexOf(workflow, "- name: Install Playwright dependencies"),
      indexOf(workflow, "- name: Run Playwright tests"));
    const action = fs.readFileSync(path.join(ACTIONS, "run-playwright/action.yml"), "utf8");
    assert.ok(action.includes("inputs.install_dependencies == 'true'"));
    assert.ok(action.includes("uses: pentaho/actions-common/.github/actions/install-playwright@ci-it"));
  });

  test("test_summary_uses_per_test_statuses_and_excludes_setup", () => {
    w.report([
      { status: "passed", suite: "setup > auth" },
      { status: "passed", suite: "chrome > expected failure" },
      { status: "failed", suite: "chrome > broken" },
      { status: "pending", suite: "firefox > pending" },
      { status: "passed", suite: "firefox > works" },
    ]);
    w.version();
    w.runScript("playwright-test-summary/summarize.cjs", { SEARCH_DIRECTORY: w.base });
    assert.deepEqual(pick(w.outputs(), ["total", "passed", "failed", "skipped"]),
      { total: "4", passed: "2", failed: "1", skipped: "1" });
    assert.equal(w.outputs().server_version, "11.0.0.4-338");
    assert.ok(w.outputs().summary.includes("chrome: 2 total"));
    assert.ok(w.outputs().summary.includes("firefox: 2 total"));
  });

  test("test_summary_accepts_array_suites", () => {
    w.report([
      { status: "passed", suite: ["setup", "auth"] },
      { status: "passed", suite: ["chrome", "plugin tests"] },
      { status: "failed", suite: ["firefox", "plugin tests"] },
      { status: "passed", suite: [] },
      { status: "passed" },
    ]);
    w.version();
    w.runScript("playwright-test-summary/summarize.cjs", { SEARCH_DIRECTORY: w.base });
    const outputs = w.outputs();
    assert.deepEqual(pick(outputs, ["total", "passed", "failed", "skipped"]),
      { total: "4", passed: "3", failed: "1", skipped: "0" });
    assert.equal(outputs.server_version, "11.0.0.4-338");
    assert.equal(outputs.ctrf_found, "true");
    for (const line of ["chrome: 1 total", "firefox: 1 total", "Tests: 2 total"]) {
      assert.ok(outputs.summary.includes(line), `Missing: ${line}`);
    }
  });

  test("test_summary_prefers_explicit_browser_and_excludes_setup_by_project", () => {
    w.report([
      { status: "passed", suite: "setup > auth", browser: "chromium" },
      { status: "passed", suite: "Login > works", browser: "chromium" },
      { status: "failed", suite: "Login > broken", browser: "firefox" },
      { status: "passed", suite: ["Login", "works"], browser: "firefox" },
    ]);
    w.runScript("playwright-test-summary/summarize.cjs", { SEARCH_DIRECTORY: w.base });
    const summary = w.outputs().summary;
    assert.equal(w.outputs().total, "3");
    assert.ok(summary.includes("chromium: 1 total"));
    assert.ok(summary.includes("firefox: 2 total, ✅ 1 passed, ❌ 1 failed"));
    assert.ok(!summary.includes("Login"));
  });

  test("test_multiline_summary_preserves_browser_names_and_line_breaks", () => {
    w.report([
      { status: "passed", suite: "chrome > works" },
      { status: "failed", suite: "firefox > broken" },
    ]);
    w.runScript("playwright-test-summary/summarize.cjs", { SEARCH_DIRECTORY: w.base, SUMMARY_FORMAT: "multiline" });
    assert.equal(w.outputs().summary,
      "Chrome: 1 total, ✅ 1 passed, ❌ 0 failed, ⏭️ 0 skipped\n" +
      "Firefox: 1 total, ✅ 0 passed, ❌ 1 failed, ⏭️ 0 skipped");
  });

  test("test_report_template_defaults_and_override", () => {
    w.report([]);
    const env = { SEARCH_DIRECTORY: w.base, GITHUB_ACTION_PATH: path.join(ACTIONS, "playwright-test-summary") };
    w.runScript("playwright-test-summary/check-reports.cjs", env);
    assert.equal(w.outputs().template_path, path.join(ACTIONS, "playwright-test-summary/custom-report.hbs"));
    fs.writeFileSync(path.join(w.base, "custom.hbs"), "{{ctrf.summary.tests}}");
    w.runScript("playwright-test-summary/check-reports.cjs", { ...env, REPORT_TEMPLATE_PATH: "custom.hbs" });
    assert.equal(w.outputs().template_path, path.join(w.base, "custom.hbs"));
    const text = w.runScript("playwright-test-summary/check-reports.cjs", {
      success: false,
      ...env,
      REPORT_TEMPLATE_PATH: "missing.hbs",
    });
    assert.ok(text.includes("::error::"));
    assert.ok(text.includes("missing.hbs"));
  });

  test("test_report_glob_and_empty_guard_preserve_paths_with_spaces", () => {
    const folder = path.join(w.base, "custom reports");
    fs.mkdirSync(folder);
    fs.writeFileSync(path.join(folder, "results.json"), "{}");
    const env = {
      SEARCH_DIRECTORY: w.base,
      GITHUB_ACTION_PATH: path.join(ACTIONS, "playwright-test-summary"),
    };
    w.runScript("playwright-test-summary/check-reports.cjs", { ...env, REPORT_PATH: "custom reports/*.json" });
    assert.equal(w.outputs().found, "true");
    assert.equal(w.outputs().report_path, path.join(folder, "*.json"));
    const text = w.runScript("playwright-test-summary/check-reports.cjs", { ...env, REPORT_PATH: "missing/*.json" });
    assert.equal(w.outputs().found, "false");
    assert.ok(text.includes("Skipping CTRF report publishing"));
  });

  test("test_report_glob_uses_reporter_semantics", async t => {
    for (const browser of ["chrome", "firefox", ".hidden"]) {
      const folder = path.join(w.base, "playwright-report", browser);
      fs.mkdirSync(folder, { recursive: true });
      fs.writeFileSync(path.join(folder, "ctrf-report.json"), "{}");
    }
    fs.mkdirSync(path.join(w.base, "only-dir.json"));
    for (const [pattern, found] of [
      ["playwright-report/{chrome,firefox}/ctrf-report.json", "true"],
      ["playwright-report/+(chrome|firefox)/ctrf-report.json", "true"],
      ["playwright-report/!(chrome)/ctrf-report.json", "true"],
      ["playwright-report/{edge,safari}/ctrf-report.json", "false"],
      ["playwright-report/.hid*/missing.json", "false"],
      ["only-dir.json", "false"],
    ]) {
      subtest(`pattern=${pattern}`, () => {
        assert.equal(w.checkReports(pattern)[0], found);
      });
    }
    fs.rmSync(path.join(w.base, "playwright-report/chrome/ctrf-report.json"));
    fs.rmSync(path.join(w.base, "playwright-report/firefox/ctrf-report.json"));
    // Like the reporter, wildcards do not match dot folders.
    assert.equal(w.checkReports("playwright-report/*/ctrf-report.json")[0], "false");
  });

  test("test_report_glob_matches_reporter_glob_package", {
    skip: isDirectory(path.join(TESTS_DIR, "node_modules/glob")) ? false
      : "npm ci --prefix .github/scripts/tests installs the reporter's glob package",
  }, () => {
    // ctrf-io/github-test-reporter v1 resolves report-path with glob.sync from glob@14.
    for (const name of ["playwright-report/chrome/ctrf-report.json", "playwright-report/firefox/ctrf-report.json",
      "playwright-report/.hidden/ctrf-report.json", "a/b/ctrf-report.json",
      "custom reports/r.json", ".dot.json"]) {
      fs.mkdirSync(path.dirname(path.join(w.base, name)), { recursive: true });
      fs.writeFileSync(path.join(w.base, name), "{}");
    }
    const patterns = ["playwright-report/{chrome,firefox}/ctrf-report.json", "**/ctrf-report.json",
      "playwright-report/*/ctrf-report.json", "*.json", "custom reports/*.json",
      "playwright-report/+(chrome|firefox)/*.json", "playwright-report/[cf]*/ctrf-report.json",
      "playwright-report/!(chrome)/*.json"];
    const script = "const fs=require('fs');const {glob}=require('glob');" +
      "const [root,...ps]=process.argv.slice(1);" +
      "for(const p of ps){const a=glob.sync(root+'/'+p).sort(),b=fs.globSync(root+'/'+p).sort();" +
      "if(JSON.stringify(a)!==JSON.stringify(b)){console.log(p,a,b);process.exitCode=1}}";
    const result = spawnSync(process.execPath, ["-e", script, w.base, ...patterns], {
      cwd: path.join(ROOT, ".github/scripts/tests"),
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });

  test("test_report_guide_and_fork_link", () => {
    w.runScript("playwright-test-summary/summarize.cjs", { SEARCH_DIRECTORY: w.base });
    const summary = fs.readFileSync(w.summary, "utf8");
    assert.ok(summary.includes("npx playwright show-report path/to/playwright-report"));
    assert.ok(summary.includes("npx playwright show-trace"));
    assert.ok(summary.includes("retained trace file"));
    assert.ok(!summary.includes("test-results"));
    fs.writeFileSync(path.join(w.base, "guide.md"), "Inspect traces");
    w.runScript("playwright-test-summary/summarize.cjs", {
      SEARCH_DIRECTORY: w.base,
      REPORT_GUIDE_PATH: "guide.md",
      GUIDE_REPOSITORY: "fork/project",
      GUIDE_REF: "feature/report",
    });
    assert.ok(fs.readFileSync(w.summary, "utf8")
      .includes("https://github.com/fork/project/blob/feature%2Freport/guide.md"));
    const text = w.runScript("playwright-test-summary/summarize.cjs", {
      success: false,
      SEARCH_DIRECTORY: w.base,
      REPORT_GUIDE_PATH: "missing.md",
    });
    assert.ok(text.includes("::error::"));
  });

  test("test_custom_report_is_wired_through_workflow", () => {
    const action = fs.readFileSync(path.join(ACTIONS, "playwright-test-summary/action.yml"), "utf8");
    assert.ok(action.includes("template-path: ${{ steps.report-files.outputs.template_path }}"));
    assert.ok(action.includes("report-path: ${{ steps.report-files.outputs.report_path }}"));
    assert.ok(action.includes("steps.report-files.outputs.found == 'true'"));
    assert.ok(action.includes("custom-report: true"));
    assert.ok(action.includes("fetch-previous-results: true"));
    assert.ok(action.includes("upload-artifact: true"));
    assert.ok(action.includes("artifact-name: ${{ inputs.artifact_name }}"));
    assert.ok(action.includes("GITHUB_TOKEN: ${{ github.token }}"));
    assert.match(action, /artifact_name:\s+description: [^\n]+\s+default: ctrf-report/);
    assert.ok(!action.includes("summary-report: true"));
    const workflow = fs.readFileSync(path.join(ROOT, ".github/workflows/integration-tests-npm.yml"), "utf8");
    assert.match(workflow, /permissions:\s+contents: read\s+actions: read/);
    assert.match(workflow, /ctrf_artifact_name:\s+type: string\s+required: false\s+default: ctrf-report/);
    for (const binding of [
      "template_path: ${{ inputs.report_template_path }}",
      "report_title: ${{ inputs.report_title }}",
      "report_path: ${{ inputs.ctrf_report_path }}",
      "artifact_name: ${{ inputs.ctrf_artifact_name }}",
      "guide_path: ${{ inputs.report_guide_path }}",
      "summary_format: ${{ inputs.summary_format }}",
      "BASE_URL: ${{ inputs.server_url }}/${{ inputs.server_context }}/",
    ]) {
      assert.ok(workflow.includes(binding), `Missing binding: ${binding}`);
    }
  });

  test("test_node_version_and_artifact_retention_are_wired", () => {
    const action = fs.readFileSync(path.join(ACTIONS, "build-plugins/action.yml"), "utf8");
    assert.ok(action.includes("dorny/test-reporter@79b4b4400dc2354b89e9dd811ef9caa9bdd4f665"));
    assert.ok(action.includes("if: ${{ always() && inputs.run_unit_tests == 'true' }}"));
    assert.ok(action.includes("cmd_type: BUILD"));
    assert.ok(action.includes('run: bash "$GITHUB_ACTION_PATH/update-summary.sh"'));
    assert.ok(!action.includes("actions/setup-node@"));
    assert.ok(!action.includes("post_build_node_version"));
    assert.ok(!action.includes("setup_node"));
    const workflow = fs.readFileSync(path.join(ROOT, ".github/workflows/build-plugins.yml"), "utf8");
    assertLess(indexOf(workflow, "- name: Set up Node"), indexOf(workflow, "- name: Retrieve settings file"));
    assertLess(indexOf(workflow, "- name: Set up Node"), indexOf(workflow, "- name: Configure npm workspace"));
    assertLess(indexOf(workflow, "- name: Set up Node"), indexOf(workflow, "- name: Build\n"));
    assert.ok(workflow.includes("if: ${{ inputs.node_version != '' }}"));
    assert.match(workflow, /node_version:\s+type: string\s+required: false\s+default: ""/);
    assert.ok(workflow.includes("uses: actions/setup-node@v6"));
    assert.ok(workflow.includes("node-version: ${{ inputs.node_version }}"));
    assert.ok(!workflow.includes("post_build_node_version"));
    assert.ok(!workflow.includes("setup_node:"));
    assert.ok(workflow.includes("retention-days: ${{ inputs.artifact_retention_days }}"));
  });

  test("test_build_summary_tracking", () => {
    useWorkflowSed(w);
    const cases = [
      { name: "success", build: "success", report: "success", conclusion: "success",
        runTests: "true", event: "pull_request", expectedBuild: "white_check_mark",
        expectedTest: "white_check_mark", url: "https://example.test/check/1" },
      { name: "build-failure", build: "failure", report: "success", conclusion: "success",
        runTests: "true", event: "push", expectedBuild: "boom", expectedTest: "boom" },
      { name: "report-failure", build: "success", report: "failure", conclusion: "",
        runTests: "true", event: "pull_request", expectedBuild: "white_check_mark", expectedTest: "boom" },
      { name: "failed-tests", build: "success", report: "success", conclusion: "failure",
        runTests: "true", event: "pull_request", expectedBuild: "white_check_mark", expectedTest: "boom" },
      { name: "tests-disabled", build: "success", report: "skipped", conclusion: "",
        runTests: "false", event: "push", expectedBuild: "white_check_mark", expectedTest: "x" },
    ];

    for (const c of cases) {
      subtest(c.name, () => {
        const temp = path.join(w.base, c.name);
        fs.mkdirSync(temp);
        w.runScript("build-plugins/update-summary.sh", {
          RUNNER_TEMP: temp,
          GITHUB_EVENT_NAME: c.event,
          BUILD_OUTCOME: c.build,
          REPORT_OUTCOME: c.report,
          REPORT_CONCLUSION: c.conclusion,
          REPORT_URL: c.url || "",
          RUN_UNIT_TESTS: c.runTests,
        });
        const icons = fs.readFileSync(path.join(temp, "icons.properties"), "utf8");
        assert.ok(icons.includes(`build=${c.expectedBuild}\n`));
        assert.ok(icons.includes(`unit_test=${c.expectedTest}\n`));
        assert.equal(icons.includes("create_tag=x\n"), c.event !== "pull_request");
        const links = path.join(temp, "unit_test_links.txt");
        assert.equal(fs.existsSync(links), Boolean(c.url));
        if (c.url) assert.equal(fs.readFileSync(links, "utf8"), `url=${c.url}\n`);
      });
    }
  });

  test("test_build_summary_tracking_preserves_existing_icons", () => {
    useWorkflowSed(w);
    fs.writeFileSync(path.join(w.base, "icons.properties"),
      "build=x\nunit_test=x\nintegration_test=white_check_mark\n");
    w.runScript("build-plugins/update-summary.sh", {
      RUNNER_TEMP: w.base,
      GITHUB_EVENT_NAME: "pull_request",
      BUILD_OUTCOME: "success",
      REPORT_OUTCOME: "success",
      REPORT_CONCLUSION: "success",
      REPORT_URL: "",
      RUN_UNIT_TESTS: "true",
    });
    assert.equal(fs.readFileSync(path.join(w.base, "icons.properties"), "utf8"),
      "build=white_check_mark\nunit_test=white_check_mark\nintegration_test=white_check_mark\n");
  });

  test("test_playwright_json_fallback", () => {
    const folder = path.join(w.base, "playwright-report");
    fs.mkdirSync(folder);
    fs.writeFileSync(path.join(folder, "results.json"), JSON.stringify({
      suites: [{
        specs: [{ tests: [{ projectName: "setup", status: "expected" }] }],
        suites: [{
          specs: [{
            tests: [
              { projectName: "chrome", status: "expected" },
              { projectName: "firefox", status: "flaky" },
              { projectName: "webkit", status: "unexpected" },
              { projectName: "chrome", status: "skipped" },
              { projectName: "firefox", status: "expected",
                expectedStatus: "failed", results: [{ status: "failed" }] },
            ],
          }],
        }],
      }],
      stats: { expected: 3, unexpected: 1, flaky: 1, skipped: 1 },
    }));
    w.runScript("playwright-test-summary/summarize.cjs", { SEARCH_DIRECTORY: folder });
    assert.deepEqual(pick(w.outputs(), ["total", "passed", "failed", "skipped"]),
      { total: "5", passed: "3", failed: "1", skipped: "1" });
    assert.equal(w.outputs().ctrf_found, "false");

    const outside = path.join(w.base, "other-results");
    fs.mkdirSync(outside);
    fs.renameSync(path.join(folder, "results.json"), path.join(outside, "results.json"));
    w.runScript("playwright-test-summary/summarize.cjs", { SEARCH_DIRECTORY: w.base });
    assert.equal(w.outputs().found, "false");
  });

  test("test_missing_reports_and_version_are_explicit", () => {
    const text = w.runScript("playwright-test-summary/summarize.cjs", { SEARCH_DIRECTORY: w.base });
    assert.ok(text.includes("no results found"));
    assert.ok(text.includes("::warning::"));
    assert.equal(w.outputs().found, "false");
    assert.equal(w.outputs().server_version, "");
  });

  test("test_malformed_report_warns", () => {
    w.report([]);
    fs.writeFileSync(path.join(w.base, "playwright-report/chrome/ctrf-report.json"), "{");
    const text = w.runScript("playwright-test-summary/summarize.cjs", { SEARCH_DIRECTORY: w.base });
    assert.ok(text.includes("Unable to parse"));
    assert.equal(w.outputs().found, "false");
  });

  test("test_report_paths_are_verbose_only", () => {
    w.report([]);
    w.version();
    const env = { SEARCH_DIRECTORY: w.base };
    assert.ok(!w.runScript("playwright-test-summary/summarize.cjs", env).includes("parsed playwright-report"));
    assert.ok(w.runScript("playwright-test-summary/summarize.cjs", { VERBOSE: "true", ...env })
      .includes("parsed playwright-report"));
  });

  test("test_practitest_preserves_browser_grouping_and_filtered_link", () => {
    fs.writeFileSync(path.join(w.base, ".env"), 'PT_PROJECT_ID="123"\nPT_TESTSET_FILTER_ID=456\n');
    w.runScript("practitest-publish/publish.sh", {
      MANUAL_API_TOKEN: "test-token",
      MANUAL_BUILD_NUMBER: "11.0.0.4-338",
      MANUAL_SERVER_CONTEXT: "sample",
      PLAYWRIGHT_PROJECT: "all",
    });
    const npm = w.commands("npm").at(-1);
    assert.equal(npm.project, null);
    assert.equal(npm.version, "11.0.0.4-338");
    assert.equal(npm.context, "sample");
    assert.deepEqual(npm.args, ["run", "upload"]);
    assert.equal(npm.env_file, path.join(w.base, ".env"));
    assert.equal(npm.results_dir, null);
    assert.equal(w.outputs().sets_url, "https://eu1-prod.practitest.app/p/123/sets?cv=456");
  });

  test("test_practitest_supports_packaged_uploader", () => {
    fs.writeFileSync(path.join(w.base, "practitest.env"), "PT_PROJECT_ID=789\n");
    w.runScript("practitest-publish/publish.sh", {
      MANUAL_API_TOKEN: "test-token",
      MANUAL_BUILD_NUMBER: "11.1.0.0-12",
      MANUAL_SERVER_CONTEXT: "sample",
      SCRIPT: "practitest:upload",
      ENV_FILE: "practitest.env",
      RESULTS_DIR: "playwright-report",
    });
    const npm = w.commands("npm").at(-1);
    assert.deepEqual(npm.args, ["run", "practitest:upload"]);
    assert.equal(npm.env_file, path.join(w.base, "practitest.env"));
    assert.equal(npm.results_dir, path.join(w.base, "playwright-report"));
    assert.equal(w.outputs().sets_url, "https://eu1-prod.practitest.app/p/789/sets");
  });

  test("test_practitest_requires_env_file", () => {
    const text = w.runScript("practitest-publish/publish.sh", {
      success: false,
      MANUAL_API_TOKEN: "test-token",
      MANUAL_BUILD_NUMBER: "11.0",
      ENV_FILE: "missing.env",
    });
    assert.ok(text.includes("Practitest env file not found"));
    assert.ok(!(fs.existsSync(w.log) && w.commands("npm").length > 0));
  });

  test("test_practitest_requires_token_and_propagates_upload_failure", () => {
    fs.writeFileSync(path.join(w.base, ".env"), "PT_PROJECT_ID=123\n");
    w.runScript("practitest-publish/publish.sh", {
      success: false,
      MANUAL_API_TOKEN: "",
      MANUAL_BUILD_NUMBER: "11.0",
    });
    w.runScript("practitest-publish/publish.sh", {
      success: false,
      MANUAL_API_TOKEN: "test-token",
      MANUAL_BUILD_NUMBER: "11.0",
      FAIL_COMMAND: "npm run",
    });
  });

  test("test_practitest_link_validation_and_project_override", () => {
    fs.writeFileSync(path.join(w.base, ".env"), "PT_PROJECT_ID=invalid\n");
    w.runScript("practitest-publish/link.cjs", { success: false });
    w.runScript("practitest-publish/link.cjs", { PROJECT_ID: "123" });
    assert.equal(w.outputs().sets_url, "https://eu1-prod.practitest.app/p/123/sets");
  });

  test("test_log_capture_and_verbose_console", () => {
    const env = {
      LOG_DIRECTORY: path.join(w.base, "logs"),
      PAS_CONTAINER: "pas",
      POSTGRES_CONTAINER: "postgres",
    };
    assert.ok(!w.runScript("collect-service-logs/collect.sh", env).includes("service console output"));
    assert.ok(fs.readFileSync(path.join(w.base, "logs/postgres.log"), "utf8").includes("service console output"));
    assert.ok(w.runScript("collect-service-logs/collect.sh", { VERBOSE: "true", ...env })
      .includes("service console output"));
    assert.ok(w.runScript("collect-service-logs/collect.sh", { FAIL_COMMAND: "docker logs", ...env })
      .includes("::warning::"));
  });

  test("test_notifications_include_setup_failure_and_escape_json", () => {
    w.runScript("notify-integration-tests/payload.sh", {
      SETUP_RESULT: "failure",
      TESTS_RESULT: "skipped",
      SLACK_CHANNEL: "ci",
      TESTS_SUMMARY: 'chrome: "failed"\nnext line',
      SERVER_VERSION: "11.0",
      SERVER_BUILD_NAME: "pdia-master",
      SERVER_CONTEXT: "sample",
      PLAYWRIGHT_PROJECT: "chrome",
      BRANCH: 'branch"with-quotes',
      EVENT_NAME: "pull_request",
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_REPOSITORY: "owner/repo",
      GITHUB_RUN_ID: "123",
      GITHUB_ACTOR: "tester",
    });
    const payload = JSON.parse(w.outputs().json);
    assert.equal(payload.status, "failure");
    assertIn('chrome: "failed"\nnext line', payload.attachments[0].fields.map(field => field.value));
  });

  test("test_pull_request_notification_keeps_caller_message", () => {
    const [title, payload] = w.pullRequestNotification({
      RESULTS: "success skipped failure",
      SERVER_VERSION: "11.0",
      TESTS_SUMMARY: 'chrome: "failed"',
      JOBS_SUMMARY: "Build: success, Tests: failure",
    });
    assert.equal(title, "PR Workflow #42");
    assert.equal(payload.status, "failure");
    assert.equal(payload.attachments[0].title, "PR Workflow #42");
    assert.deepEqual(payload.attachments[0].fields.map(field => field.value), [
      "Event: <https://github.com/owner/repo/actions/runs/123|pull_request>",
      "Status: failure ❌",
      "Branch: feature",
      "PR: <https://github.com/owner/repo/pull/42|#42>",
      "Version: 11.0",
      'chrome: "failed"',
      "Build: success, Tests: failure",
    ]);
    assert.equal(payload.attachments[0].footer, "by tester");
  });

  test("test_pull_request_notification_status_and_defaults", () => {
    const [, payload] = w.pullRequestNotification({ RESULTS: "success cancelled" });
    const fields = payload.attachments[0].fields.map(field => field.value);
    assert.equal(payload.status, "cancelled");
    assert.ok(fields.includes("Status: cancelled ⚠️"));
    assert.ok(fields.includes("Version: unknown"));
    assert.ok(fields.includes("Tests: no results found"));
    const [, second] = w.pullRequestNotification({ RESULTS: "success skipped" });
    assert.equal(second.status, "success");
  });

  test("test_shared_notification_preserves_integration_test_message", () => {
    w.runScript("notify-slack/payload.sh", {
      FORMAT: "integration_tests",
      WORKFLOW_NAME: "Nightly",
      SETUP_RESULT: "success",
      TESTS_RESULT: "failure",
      SLACK_CHANNEL: "ci",
      TESTS_SUMMARY: "chrome: 2 passed, 1 failed",
      SERVER_VERSION: "11.0",
      SERVER_BUILD_NAME: "pdia-master",
      SERVER_CONTEXT: "sample",
      PLAYWRIGHT_PROJECT: "chrome",
      PRACTITEST_URL: "https://practitest.example/sets",
      BRANCH: "master",
      EVENT_NAME: "schedule",
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_REPOSITORY: "owner/repo",
      GITHUB_RUN_ID: "123",
      GITHUB_ACTOR: "tester",
    });
    const payload = JSON.parse(w.outputs().json);
    assert.equal(payload.status, "failure");
    assert.equal(payload.attachments[0].title, "Pentaho Plugin Integration Tests");
    assert.deepEqual(payload.attachments[0].fields.map(field => field.value), [
      "Event: <https://github.com/owner/repo/actions/runs/123|schedule>",
      "Status: failure",
      "Branch: master",
      "Version: 11.0",
      "Server: pdia-master (sample), Project: chrome",
      "chrome: 2 passed, 1 failed",
      "Practitest: <https://practitest.example/sets|Test Sets & Runs>",
      "Setup: success, Integration tests: failure",
    ]);
    assert.equal(payload.attachments[0].footer, "by tester");
  });

  test("test_shared_notification_preserves_integration_skipped_status", () => {
    w.runScript("notify-slack/payload.sh", {
      FORMAT: "integration_tests",
      WORKFLOW_NAME: "Nightly",
      SETUP_RESULT: "success",
      TESTS_RESULT: "skipped",
      SLACK_CHANNEL: "ci",
      SERVER_BUILD_NAME: "pdia-master",
      SERVER_CONTEXT: "sample",
      PLAYWRIGHT_PROJECT: "all",
      BRANCH: "master",
      EVENT_NAME: "workflow_dispatch",
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_REPOSITORY: "owner/repo",
      GITHUB_RUN_ID: "123",
      GITHUB_ACTOR: "tester",
    });
    const payload = JSON.parse(w.outputs().json);
    const fields = payload.attachments[0].fields.map(field => field.value);
    assert.equal(payload.status, "skipped");
    assert.ok(fields.includes("Tests: no results found"));
    assert.ok(!fields.join("\n").includes("Practitest: <"));
  });

  test("test_scheduler_nightly_notification_preserves_title_icons_and_browser_lines", () => {
    const summary = "Chrome: 2 passed\nFirefox: 1 failed";
    w.runScript("notify-slack/payload.sh", {
      FORMAT: "integration_tests",
      NOTIFICATION_TITLE: "Scheduler PAS Integration Tests",
      STATUS_ICONS: "true",
      SETUP_RESULT: "success",
      TESTS_RESULT: "failure",
      SLACK_CHANNEL: "ci",
      TESTS_SUMMARY: summary,
      SERVER_BUILD_NAME: "pdia-master",
      SERVER_CONTEXT: "sample",
      PLAYWRIGHT_PROJECT: "all",
      BRANCH: "master",
      EVENT_NAME: "schedule",
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_REPOSITORY: "owner/repo",
      GITHUB_RUN_ID: "123",
      GITHUB_ACTOR: "tester",
    });
    const payload = JSON.parse(w.outputs().json);
    assert.equal(w.outputs().title, "Scheduler PAS Integration Tests");
    assert.equal(payload.attachments[0].title, "Scheduler PAS Integration Tests");
    const fields = payload.attachments[0].fields.map(field => field.value);
    assert.ok(fields.includes("Status: failure ❌"));
    assert.ok(fields.includes(summary));
  });

  test("test_actions_use_container_safe_action_path", async t => {
    // ${{ github.action_path }} expands to the host path, which does not exist in job containers.
    for (const entry of fs.readdirSync(ACTIONS, { withFileTypes: true })) {
      const actionFile = path.join(ACTIONS, entry.name, "action.yml");
      if (!entry.isDirectory() || !fs.existsSync(actionFile)) {
        continue;
      }
      subtest(`action=${entry.name}`, () => {
        assert.doesNotMatch(fs.readFileSync(actionFile, "utf8"), /\$\{\{\s*github\.action_path/);
      });
    }
  });

  test("test_actions_never_enable_shell_tracing", async t => {
    // xtrace prints expanded commands, exposing derived credentials that secret masking misses.
    const tracing = /set\s+-[a-wyz]*x|set\s+-o\s+xtrace|bash\s+-[a-wyz]*x|\(-x\)/;
    for (const file of walkFiles(ACTIONS)) {
      if ([".yml", ".sh"].includes(path.extname(file))) {
        subtest(`path=${path.relative(ACTIONS, file)}`, () => {
          assert.doesNotMatch(fs.readFileSync(file, "utf8"), tracing);
        });
      }
    }
  });
});
