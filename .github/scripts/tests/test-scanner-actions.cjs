"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");

const ROOT = path.resolve(__dirname, "../../..");
const ACTIONS = path.join(ROOT, ".github/actions");
const WORKFLOWS = path.join(ROOT, ".github/workflows");
const PREPARE = path.join(ACTIONS, "frogbot-scan/prepare.sh");
const MAVEN_EXCLUSIONS = "*.git*;*node_modules*;*target*;*venv*;*test*;*resources-filtered*";
const NPM_EXCLUSIONS = "*.git*;*node_modules*;*dist*;*build*;*coverage*;*.next*;*.nuxt*;*test*";

function fakeCurl() {
  const fs = require("node:fs");
  const args = process.argv.slice(2);
  fs.appendFileSync(process.env.CURL_LOG, JSON.stringify(args) + "\n");
  if (process.env.CURL_FAIL === "true") {
    console.error("simulated curl failure");
    process.exit(7);
  }
  const url = new URL(args.at(-1));
  const module = url.pathname.split("/contents/")[1];
  const responses = JSON.parse(process.env.CURL_RESPONSES);
  process.stdout.write(responses[module] || "200");
}

function withWorkspace(callback) {
  const base = fs.mkdtempSync(path.join(__dirname, ".scanner-workspace-"));
  try {
    const bin = path.join(base, "bin");
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, "curl"),
      "#!" + process.execPath + "\n(" + fakeCurl.toString() + ")();\n", { mode: 0o755 });
    const output = path.join(base, "output");
    const log = path.join(base, "curl.jsonl");
    const env = {
      ...process.env,
      PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      GITHUB_OUTPUT: output,
      CURL_LOG: log,
      CURL_FAIL: "false",
      CURL_RESPONSES: "{}",
      MAVEN_MODE: "validate",
      MAVEN_MODULES: "",
      MAVEN_DIRECTIVES: "",
      REPOSITORY: "pentaho/example",
      BASE_REF: "main",
      JF_GIT_TOKEN: "fake-git-token",
    };
    callback({
      run(overrides) {
        fs.writeFileSync(output, "");
        fs.writeFileSync(log, "");
        const result = spawnSync("bash", [PREPARE], {
          cwd: base,
          env: { ...env, ...overrides },
          encoding: "utf8",
        });
        return {
          ...result,
          output: fs.readFileSync(output, "utf8"),
          requests: fs.readFileSync(log, "utf8").split("\n").filter(Boolean).map(JSON.parse),
        };
      },
    });
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
}

function readAction(name) {
  return fs.readFileSync(path.join(ACTIONS, name, "action.yml"), "utf8");
}

function readWorkflow(name) {
  return fs.readFileSync(path.join(WORKFLOWS, name), "utf8");
}

function steps(workflow, name) {
  return workflow.split(/^      - name: /m).filter(block => block.split("\n", 1)[0] === name);
}

function actionSteps(action, name) {
  return action.split(/^    - name: /m).filter(block => block.split("\n", 1)[0] === name);
}

function sonarArguments(options) {
  const action = readAction("sonarqube-scan");
  const match = action.match(/^\s+sonar_commands: >-\n((?: {10}.+\n?)+)/m);
  assert.ok(match, "Missing SonarQube command");
  const template = match[1].trim().split("\n").map(line => line.trim()).join(" ");
  const rendered = template.replace(/\$\{\{\s*(.*?)\s*\}\}/g, (_match, expression) => {
    switch (expression) {
      case "github.repository":
        return options.repository;
      case "inputs.project_key":
        return options.projectKey;
      case "inputs.host_url":
        return options.hostUrl;
      case "inputs.token":
        return options.token;
      default:
        if (expression.startsWith("inputs.working_directory != '' && format(")) {
          assert.ok(expression.includes("'-Dsonar.working.directory={0}', inputs.working_directory"));
          return options.workingDirectory ? `-Dsonar.working.directory=${options.workingDirectory}` : "";
        }
        if (expression.startsWith("inputs.pull_request == 'true' && format(")) {
          assert.ok(expression.includes("github.event.number, github.event.pull_request.head.ref, github.event.pull_request.base.ref"));
          return options.pullRequest
            ? `-Dsonar.pullrequest.key=${options.number} -Dsonar.pullrequest.branch=${options.branch} -Dsonar.pullrequest.base=${options.base}`
            : "";
        }
        throw new Error(`Unexpected SonarQube expression: ${expression}`);
    }
  });
  assert.ok(rendered.startsWith("(") && rendered.endsWith(")"), rendered);
  const result = spawnSync("python3", [
    "-c",
    "import json, shlex, sys; print(json.dumps(shlex.split(sys.argv[1][1:-1])))",
    rendered,
  ], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("SonarQube command preserves PR and merge arguments", () => {
  const defaults = {
    repository: "pentaho/example",
    projectKey: "example-project",
    hostUrl: "https://sonar.example",
    token: "fake-sonar-token",
    number: "42",
    branch: "feature/scanner",
    base: "main",
  };
  const common = [
    "-Dsonar.projectKey=example-project",
    "-Dsonar.host.url=https://sonar.example",
    "-Dsonar.token=fake-sonar-token",
  ];
  assert.deepEqual(sonarArguments({ ...defaults, pullRequest: true }), [
    "-Dsonar.links.scm=https://github.com/pentaho/example",
    ...common,
    "-Dsonar.pullrequest.key=42",
    "-Dsonar.pullrequest.branch=feature/scanner",
    "-Dsonar.pullrequest.base=main",
  ]);
  assert.deepEqual(sonarArguments({ ...defaults, workingDirectory: "/tmp/.scannerwork" }), [
    "-Dsonar.links.scm=https://github.com/pentaho/example",
    "-Dsonar.working.directory=/tmp/.scannerwork",
    ...common,
  ]);
  assert.deepEqual(sonarArguments(defaults), [
    "-Dsonar.links.scm=https://github.com/pentaho/example",
    ...common,
  ]);
});

test("FrogBot extracts project flags from Maven directives", () => {
  withWorkspace(workspace => {
    for (const [directives, expected] of [
      ["", ""],
      ["-B -pl module-a,module-b -am", "-pl module-a,module-b"],
      ["--projects=module-a -pl 'module-b,module-c' --projects module-d", "-pl module-a,module-b,module-c,module-d"],
      ["-Dprofile='one two'\n-pl \"module-a,module-b\"\n--projects=module-c", "-pl module-a,module-b,module-c"],
      ["-DskipTests -am", ""],
      ["-pl", ""],
      ["-f plugins/pom.xml -pl scheduler -am", "-f plugins/pom.xml -pl scheduler"],
      ["--file=a/pom.xml -B --file b/pom.xml --projects=x", "-f b/pom.xml -pl x"],
      ["-f plugins/pom.xml -DskipTests", "-f plugins/pom.xml"],
      ["-f 'my plugins/pom.xml' -pl scheduler", ""],
      ["-fplugins/pom.xml -pl scheduler", "-f plugins/pom.xml -pl scheduler"],
      ["-ff -fae -fn -pl module-a", "-pl module-a"],
      ["-f a/pom.xml -fae -fb/pom.xml --projects=x", "-f b/pom.xml -pl x"],
    ]) {
      const result = workspace.run({ MAVEN_MODE: "directives", MAVEN_DIRECTIVES: directives });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.output, `maven_args=${expected}\n`, directives);
      assert.deepEqual(result.requests, []);
    }
  });
});

test("FrogBot filters only modules present on the PR base branch", () => {
  withWorkspace(workspace => {
    const result = workspace.run({ MAVEN_MODULES: "module-a, module-b", BASE_REF: "release/1.0" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.output, "maven_args=-pl module-a,module-b\n");
    assert.equal(result.requests.length, 2);
    for (const [index, module] of ["module-a", "module-b"].entries()) {
      assert.deepEqual(result.requests[index], [
        "-sS", "-o", "/dev/null", "-w", "%{http_code}",
        "-H", "Authorization: Bearer fake-git-token",
        "-H", "Accept: application/vnd.github+json",
        `https://api.github.com/repos/pentaho/example/contents/${module}?ref=release/1.0`,
      ]);
    }
  });
});

test("FrogBot removes the module filter for missing, empty, or invalid modules", () => {
  withWorkspace(workspace => {
    for (const overrides of [
      { MAVEN_MODULES: "module-a,module-b", CURL_RESPONSES: '{"module-b":"404"}' },
      { MAVEN_MODULES: "" },
      { MAVEN_MODULES: "module-a,,module-b" },
    ]) {
      const result = workspace.run(overrides);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.output, "maven_args=\n");
      assert.match(result.stdout, /Skipping module filtering/);
    }
  });
});

test("FrogBot preparation surfaces failed requests and unsupported modes", () => {
  withWorkspace(workspace => {
    const network = workspace.run({ MAVEN_MODULES: "module-a", CURL_FAIL: "true" });
    assert.notEqual(network.status, 0);
    assert.equal(network.output, "");
    assert.match(network.stderr, /simulated curl failure/);
    assert.match(network.stdout, /::warning::Unable to validate Maven modules/);

    const mode = workspace.run({ MAVEN_MODE: "unknown" });
    assert.notEqual(mode.status, 0);
    assert.equal(mode.output, "");
    assert.match(mode.stderr, /Unsupported FrogBot Maven selection mode/);

    const invalid = workspace.run({ MAVEN_MODE: "directives", MAVEN_DIRECTIVES: '-pl "module-a' });
    assert.notEqual(invalid.status, 0);
    assert.equal(invalid.output, "");
    assert.match(invalid.stderr, /No closing quotation/);

    const newline = workspace.run({ MAVEN_MODE: "directives", MAVEN_DIRECTIVES: '-pl "module-a\nmodule-b"' });
    assert.notEqual(newline.status, 0);
    assert.equal(newline.output, "");
    assert.match(newline.stderr, /must not contain line breaks/);
  });
});

test("scanner actions prepare and forward scan configuration", () => {
  const sonar = readAction("sonarqube-scan");
  assert.ok(sonar.includes("uses: lumada-common-services/gh-composite-actions@stable"));
  assert.ok(sonar.includes("sonar_utility: sonar-scanner"));
  assert.match(sonar, /pull_request:\s+description: [^\n]+\s+default: "false"/);
  assert.match(sonar, /working_directory:\s+description: [^\n]+\s+default: ""/);

  const frog = readAction("frogbot-scan");
  assert.ok(frog.includes(`default: "${MAVEN_EXCLUSIONS}"`));
  assert.match(frog, /maven_mode:\s+description: [^\n]+\s+default: "none"/);
  const prepare = actionSteps(frog, "Prepare FrogBot scan");
  assert.equal(prepare.length, 1);
  for (const binding of [
    "if: ${{ inputs.maven_mode != 'none' }}",
    "continue-on-error: ${{ inputs.maven_mode == 'validate' }}",
    "MAVEN_MODE: ${{ inputs.maven_mode }}",
    "MAVEN_MODULES: ${{ inputs.modules }}",
    "MAVEN_DIRECTIVES: ${{ inputs.maven_directives }}",
    "REPOSITORY: ${{ github.repository }}",
    "BASE_REF: ${{ github.event.pull_request.base.ref }}",
    "JF_GIT_TOKEN: ${{ inputs.git_token }}",
    'run: bash "$GITHUB_ACTION_PATH/prepare.sh"',
  ]) {
    assert.ok(prepare[0].includes(binding), `Missing FrogBot preparation binding: ${binding}`);
  }

  const withoutMaven = actionSteps(frog, "FrogBot scan");
  const withMaven = actionSteps(frog, "FrogBot scan with Maven");
  assert.equal(withoutMaven.length, 1);
  assert.equal(withMaven.length, 1);
  assert.ok(withoutMaven[0].includes("if: ${{ inputs.maven_mode == 'none' }}"));
  assert.ok(!withoutMaven[0].includes("MAVEN_ARGS:"), "Non-Maven scans must retain the caller's environment");
  assert.ok(withMaven[0].includes("if: ${{ inputs.maven_mode != 'none' }}"));
  assert.ok(withMaven[0].includes("MAVEN_ARGS: ${{ steps.prepare.outputs.maven_args }}"));
  for (const step of [withoutMaven[0], withMaven[0]]) {
    for (const binding of [
      "uses: lumada-common-services/gh-composite-actions@stable",
      "JF_URL: ${{ inputs.artifactory_url }}",
      "JF_ACCESS_TOKEN: ${{ inputs.access_token }}",
      "JF_GIT_TOKEN: ${{ inputs.git_token }}",
      "GIT_REPO_OWNER: ${{ github.repository_owner }}",
      "GIT_REPO_NAME: ${{ github.event.repository.name }}",
      "JF_PATH_EXCLUSIONS: ${{ inputs.path_exclusions }}",
      "PULL_REQUEST_NUMBER: ${{ github.event.number }}",
    ]) {
      assert.ok(step.includes(binding), `Missing FrogBot binding: ${binding}`);
    }
  }
});

test("all affected workflows call scanner actions with original conditions and options", () => {
  const cases = [
    { file: "pr.yml", ref: "stable", sonarCount: 1, pullRequest: true, frog: true },
    { file: "pr-npm.yml", ref: "stable", sonarCount: 1, pullRequest: true, frog: true, npm: true },
    { file: "merge.yml", ref: "stable", sonarCount: 2, merge: true },
    { file: "merge-npm.yml", ref: "stable", sonarCount: 1, merge: true },
    { file: "build-plugins.yml", ref: "stable", sonarCount: 1, frog: true, plugin: true },
  ];
  for (const item of cases) {
    const workflow = readWorkflow(item.file);
    const sonar = steps(workflow, "Sonarqube scan");
    assert.equal(sonar.length, item.sonarCount, item.file);
    for (const step of sonar) {
      assert.ok(step.includes(`uses: pentaho/actions-common/.github/actions/sonarqube-scan@${item.ref}`), item.file);
      assert.ok(step.includes("host_url: ${{ env.SONAR_HOST_URL }}"), item.file);
      assert.ok(step.includes("token: ${{ env.SONAR_LOGIN }}"), item.file);
      assert.ok(step.includes(item.plugin
        ? "project_key: ${{ inputs.sonar_project_key }}"
        : "project_key: ${{ env.SONAR_PROJECT_KEY }}"), item.file);
      if (item.pullRequest) assert.ok(step.includes('pull_request: "true"'), item.file);
      if (item.merge) {
        assert.ok(step.includes("continue-on-error: true"), item.file);
        assert.ok(step.includes("working_directory: /tmp/.scannerwork"), item.file);
        assert.ok(!step.includes("pull_request:"), item.file);
      }
      if (item.plugin) {
        assert.ok(step.includes("if: ${{ inputs.sonar_project_key != '' }}"));
        assert.ok(step.includes("pull_request: ${{ github.event_name == 'pull_request' }}"));
      }
    }
    if (item.file === "merge.yml") {
      assert.ok(sonar[1].includes("if: ${{ inputs.run_snapshot == false }}"));
    }

    const frog = steps(workflow, "FrogBot scan");
    assert.equal(frog.length, item.frog ? 1 : 0, item.file);
    assert.equal(steps(workflow, "Prepare FrogBot scan").length, 0, item.file);
    assert.equal(steps(workflow, "Prepare Frogbot scan").length, 0, item.file);
    assert.ok(!workflow.includes("frogbot-maven-args"), item.file);
    if (!item.frog) continue;
    const step = frog[0];
    assert.ok(step.includes(`uses: pentaho/actions-common/.github/actions/frogbot-scan@${item.ref}`), item.file);
    assert.ok(step.includes("artifactory_url: https://${{ vars.ARTIFACTORY_HOST }}"), item.file);
    assert.ok(step.includes("access_token: ${{ secrets.JF_ACCESS_TOKEN }}"), item.file);
    assert.ok(step.includes("git_token: ${{ secrets.HV_ACTIONS_GIT_TOKEN }}"), item.file);
    assert.ok(!step.includes("MAVEN_ARGS:"), item.file);
    if (item.npm) {
      assert.ok(step.includes(`path_exclusions: "${NPM_EXCLUSIONS}"`));
      assert.ok(!step.includes("maven_mode:"));
    }
    if (item.plugin) {
      const condition = "if: ${{ inputs.frogbot_scan && github.event_name == 'pull_request' }}";
      assert.ok(step.includes(condition));
      assert.ok(step.includes("maven_mode: directives"));
      assert.ok(step.includes("maven_directives: ${{ inputs.additional_mvn_directives }}"));
    } else if (!item.npm) {
      assert.ok(step.includes("maven_mode: validate"));
      assert.ok(step.includes("modules: ${{ inputs.modules_to_build || steps.change_detection.outputs.changed_modules }}"));
    }
  }
});

test("scanner regressions run when any affected workflow changes", () => {
  const workflow = readWorkflow("script-tests.yml");
  for (const file of ["pr.yml", "pr-npm.yml", "merge.yml", "merge-npm.yml", "build-plugins.yml"]) {
    assert.ok(workflow.includes(`'.github/workflows/${file}'`), file);
  }
  assert.ok(workflow.includes("node --test .github/scripts/tests/test-plugin-workflows.cjs .github/scripts/tests/test-scanner-actions.cjs"));
});
