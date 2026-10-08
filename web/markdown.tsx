import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

/**
 * Model output as markdown. Raw HTML is never rendered (react-markdown's default) and links
 * open in a new tab without opener access: this page holds the session cookie and a terminal.
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
        }}
      >
        {text}
      </ReactMarkdown>
    </div>
  );
}
