import { describe, expect, test } from "bun:test";
import { rawDataCommand } from "../src/workspace/datarules";

const root = "/work/case";
const data = new Set(["investigation-kibana.csv", "clients.json"]);

describe("sensitive workspaces: raw data through the shell", () => {
  // The exact commands an agent used to send raw rows in a real session.
  const leaked = [
    `wc -l *.csv && for f in *.csv; do echo "=== $f"; head -c 3000 "$f"; echo; done`,
    `python3 -I -c "\nimport csv\nr=list(csv.DictReader(open('investigation-kibana.csv')))\n"`,
    `python3 /tmp/an/a.py .`,
    `cat clients.json | jq '.[0]'`,
    `node -e "console.log(require('fs').readFileSync('x'))"`,
    `python3 - <<'EOF'\nprint(open('data').read())\nEOF`,
    `duckdb -c "select * from 'investigation-kibana.csv'"`,
    `awk -F, '{print $3}' investigation-kibana.csv`,
  ];
  for (const c of leaked) test(`blocks: ${c.split("\n")[0]!.slice(0, 60)}`, () => expect(rawDataCommand(c, root, data)).not.toBeNull());

  const fine = [
    `ls -la && file * | head -50`,
    `ls *.csv`,
    `wc -l investigation-kibana.csv`,
    `find . -name "*.csv"`,
    `git status --short`,
    `bun test`,
    `cat package.json`,
    `python3 scripts/report.py`,
    `node ./tools/check.mjs`,
  ];
  for (const c of fine) test(`allows: ${c}`, () => expect(rawDataCommand(c, root, data)).toBeNull());

  test("find -exec is not 'metadata only'", () => expect(rawDataCommand(`find . -name "*.csv" -exec cat {} \;`, root, data)).not.toBeNull());
});
