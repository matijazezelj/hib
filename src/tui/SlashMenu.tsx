import { Box, Text } from "ink";
import type { Suggestion } from "./complete";

/** The suggestion list under the prompt: ↑/↓ to move, Tab to complete, Enter to run. */
export function SlashMenu({ items, selected }: { items: Suggestion[]; selected: number }) {
  if (!items.length) return null;
  const width = Math.max(...items.map((s) => s.label.length)) + 2;
  return (
    <Box flexDirection="column" paddingLeft={2}>
      {items.map((s, i) => (
        <Text key={s.label} inverse={i === Math.min(selected, items.length - 1)}>
          {s.label.padEnd(width)}
          <Text dimColor>{s.desc}</Text>
        </Text>
      ))}
      <Text dimColor>tab complete · ↑↓ select · enter run · esc clear</Text>
    </Box>
  );
}
