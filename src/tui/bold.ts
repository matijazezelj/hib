const ON = "\x1b[1m";
const OFF = "\x1b[22m";
const SPAN = /\*\*(?=\S)(.+?)(?<=\S)\*\*/g;

/** `**x**` → ANSI bold; text inside `code` spans is left as is. */
export function bold(text: string): string {
  return text
    .split(/(`[^`\n]*`)/)
    .map((part, i) => (i % 2 ? part : part.replace(SPAN, `${ON}$1${OFF}`)))
    .join("");
}

/**
 * Streaming version: emits text as it arrives but holds back an opened `**` span until it closes,
 * or until the line ends, when an unmatched `**` is printed as is.
 */
export class BoldStream {
  private buf = "";

  feed(chunk: string): string {
    this.buf += chunk;
    const nl = this.buf.lastIndexOf("\n");
    const done = nl >= 0 ? this.buf.slice(0, nl + 1) : "";
    let rest = nl >= 0 ? this.buf.slice(nl + 1) : this.buf;
    let cut = rest.length - /\**$/.exec(rest)![0].length;
    const marks = [...rest.slice(0, cut).matchAll(/\*\*/g)];
    if (marks.length % 2) cut = marks[marks.length - 1]!.index!;
    this.buf = rest.slice(cut);
    rest = rest.slice(0, cut);
    return bold(done) + bold(rest);
  }

  flush(): string {
    const out = bold(this.buf);
    this.buf = "";
    return out;
  }
}
