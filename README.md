# DetectHQ Sigma Rules

Community detection rules auto-generated from threat intelligence analysis.

Published by [DetectHQ](https://detecthq.in) — AI-powered threat intelligence by [GanaSec](https://ganasec.com).

## Structure

```
rules/
  YYYY-MM/
    slug-name.yml      # Sigma rules
    slug-name.yar      # YARA rules
```

## Usage

Import rules directly into your SIEM or use with [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
sigma convert -t splunk rules/2026-07/*.yml
```

## License

These rules are provided as-is for defensive use. Attribution appreciated.

---
*Auto-published from [DetectHQ.in](https://detecthq.in) threat intelligence blog posts.*
