import { expect, test } from "bun:test";
import { bold, BoldStream } from "../src/tui/bold";

const B = (s: string) => `\x1b[1m${s}\x1b[22m`;

test("**x** becomes bold, inline code and lone ** stay as is", () => {
  expect(bold("a **b c** d **e**")).toBe(`a ${B("b c")} d ${B("e")}`);
  expect(bold("call `f(**kwargs)` and **go**")).toBe(`call \`f(**kwargs)\` and ${B("go")}`);
  expect(bold("2 ** 3 is 8")).toBe("2 ** 3 is 8");
});

test("streaming holds an open span until it closes, whatever the chunking", () => {
  const text = "Result: **impossible travel** from *HR* to **JP**.\nNext ** line\nend";
  for (const size of [1, 2, 3, 5, 7, 100]) {
    const s = new BoldStream();
    let out = "";
    for (let i = 0; i < text.length; i += size) out += s.feed(text.slice(i, i + size));
    out += s.flush();
    expect(out).toBe(bold(text));
  }
});
