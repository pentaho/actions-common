"use strict";

const fs = require("node:fs");
const projectOverride = process.env.PROJECT_ID;
const envFile = process.env.PT_ENV_FILE || ".env";
if (fs.existsSync(envFile)) process.loadEnvFile(envFile);
const project = projectOverride || process.env.PT_PROJECT_ID || "";
const filter = process.env.PT_TESTSET_FILTER_ID || "";
if (!/^\d+$/.test(project) || (filter && !/^\d+$/.test(filter))) {
  console.error("::error::Practitest links require numeric PT_PROJECT_ID and optional PT_TESTSET_FILTER_ID in the Practitest env file.");
  process.exit(1);
}
const url = `https://eu1-prod.practitest.app/p/${project}/sets${filter ? `?cv=${filter}` : ""}`;
fs.appendFileSync(process.env.GITHUB_OUTPUT, `sets_url=${url}\n`);
fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,
  `## Practitest\n- [Test Library](https://eu1-prod.practitest.app/p/${project}/tests)\n- [Test Sets & Runs](${url})\n`);
if (process.env.VERBOSE === "true") console.log(`Practitest results: ${url}`);
