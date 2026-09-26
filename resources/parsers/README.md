# Parsers

**Status: placeholder only (Phase 3). Not populated, no loader.**

`MarkdownFrontmatterParser.ts` (reused by this phase's `PromptLoader.ts`)
and the Phase 3 `_parse_prompt_file`/`_parse_policy_file` functions are
parsing *logic*, not hardcoded *data* — there's nothing here to
externalize as a resource file. Left empty pending a concrete need (e.g. a
future format-mapping table that's actually data-shaped).
