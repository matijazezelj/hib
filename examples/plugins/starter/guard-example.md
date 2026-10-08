---
kind: guard
# Words and patterns that must never leave the machine. Guard plugins can only tighten rules.
terms: []
askOn: [TICKET]
patterns:
  - { category: TICKET, regex: "\\b[A-Z]{2,6}-\\d{2,6}\\b" }
---
