import { expect, test } from "bun:test";
import { resetSandboxProbe, sandboxAvailable, sandboxProblem } from "../src/workspace/sandbox";

test("the sandbox probe is consistent and explains a failure", () => {
  resetSandboxProbe();
  const problem = sandboxProblem();
  expect(sandboxAvailable()).toBe(problem === null);
  if (problem !== null) expect(problem.length).toBeGreaterThan(10);
  expect(sandboxProblem()).toBe(problem); // cached
});
