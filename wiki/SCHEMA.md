# Wiki Schema

This file is the configuration for this wiki. It documents the conventions, page types, tag taxonomy, and any workflow customizations. The LLM reads this first when entering the wiki, and its conventions override the defaults documented in the `llm-wiki` skill.

This file is **co-evolved with the user**. When the LLM notices a recurring pattern in your edits or feedback that isn't here, it will propose adding it. When something here stops fitting, prune it.

## Wiki location

- Wiki root: `wiki/`
- Raw sources: `raw/`
- Asset/image storage: `raw/assets/`

## Page types

This wiki uses these page types, each with a dedicated subdirectory:

- `source` (in `wiki/sources/`) — one summary page per ingested source.
- `entity` (in `wiki/entities/`) — pages about specific things: people, papers, products, places, organizations.
- `concept` (in `wiki/concepts/`) — pages about ideas, methods, frameworks, abstractions.
- `synthesis` (in `wiki/synthesis/`) — cross-cutting analyses, comparisons, query answers filed back.

Add additional types here as the wiki evolves.

## Tag taxonomy

Keep this list small and disciplined — a wiki with 200 tags has effectively no tags. Current set:

- `architecture` — how the server is structured and why; module boundaries and their rationale.
- `contract` — an invariant call sites must honour; getting it wrong is a bug, not a style choice.
- `gotcha` — a rule whose violation fails silently or far from its cause.
- `config` — settings, feature flags, and derived configuration.
- `oauth` — behaviour specified by an OAuth 2.x RFC.
- `oidc` — behaviour specified by OpenID Connect.

## Sourcing rule for a codebase wiki

This wiki's source is mutable code, not fixed documents, so the default "cite the raw file" rule is
adapted:

- Non-source pages carry `sources: [oauth-server-codebase]` and additionally cite exact
  `file:line` locations inline for each substantive claim.
- The source page records the commit it was verified at (`revision:` in its frontmatter). A claim is
  checkable against that revision rather than taken on the wiki's word.
- Prefer the code's own comments and commit messages as evidence. They record *why* a structure
  exists — reasoning that cannot be re-derived from control flow — which is the highest-value
  material this codebase offers.
- Never promote an inference about what code probably does into a typed graph edge; typed edges need
  a quotable line.

## Page sizing

- Soft cap: 400 lines / ~2,000 words. Consider splitting beyond this.
- Hard cap: 800 lines. Must split.

## Frontmatter requirements

Every page must have:
- `type`
- `title`
- `tags`
- `created`
- `updated`

Plus type-specific:
- `source` pages: `authors`, `url` (if applicable), `raw`, `ingested`
- Non-source pages: `sources` listing the source-summary pages drawn from

## Optional graph metadata

Pages may declare typed graph metadata under a top-level `graph:` key. This is the source of truth for the compiled knowledge graph under `wiki/graph/`. Markdown remains canonical; the graph is a regenerable index. Pages without `graph:` still appear as nodes (derived from `type`/`kind`) and still contribute `mentions` edges from body `[[wikilinks]]`.

```yaml
graph:
  node_id: person:praney-behl       # optional; default <node_type>:<slug>
  node_type: person                  # optional; default mapped from type/kind via ontology
  canonical: true                    # mark as canonical when multiple slugs alias the same entity
  aliases: [Praney, praney@example.com]
  relationships:
    - predicate: founded
      object: company:seedblocks
      source: praney-founder-context-dump   # source-page slug
      evidence: "Solo technical founder and sole director..."
      confidence: high               # high | medium | low
      status: current                # current | historical | proposed | disputed | superseded
      # optional:
      # valid_from: 2025-01-15
      # valid_to: 2026-03-01
      # notes: "..."
      # raw_ref: "raw/founder-dump.md#L42"
      # contradicts: edge-id-or-source-slug
      # supersedes: edge-id-or-source-slug
```

Required fields on every relationship: `predicate`, `object`, `source`, `evidence`, `confidence`, `status`. Predicates and the subject/object types they accept are declared in `wiki/graph/ontology.yaml`. Typed semantic edges must be supported by an explicit source — never emit one inferred from training data alone.

## Index structure

(Update this section when sharding.)

Currently flat: a single `wiki/index.md` listing all pages.

When the wiki passes ~150 pages or `index.md` exceeds 300 lines, shard into `wiki/indexes/<type>.md` and update this section.

## Retrieval

- **Always invoke the bundled scripts through `wiki/bin/wiki.py`**, from the repo root: `python wiki/bin/wiki.py search "query" --json`. The scripts themselves live in the plugin cache under a versioned path, so hardcoded paths break on plugin upgrade; the launcher resolves the newest installed copy, passes the wiki directory, and forces UTF-8 output. Commands: `search`, `lint`, `stats`, `setup`, `graph-extract`, `graph-lint`, `graph-query`.
- Search is section-level hybrid by default: `python wiki/bin/wiki.py search "query" --json`.
- Semantic backend: local FastEmbed + sqlite-vec (`BAAI/bge-small-en-v1.5`, 384 dimensions). No wiki or query text leaves the machine.
- First semantic use downloads model artifacts to `~/.cache/llm-wiki/fastembed/`; set `FASTEMBED_CACHE_PATH` to override the model cache.
- Semantic setup verified: 2026-09-01
- `wiki/.wiki-cache/` holds regenerable retrieval artifacts: `search-index.json` (parse cache) and `embeddings.sqlite` (section metadata + sqlite-vec vectors). Safe to delete; never edit by hand; gitignored.
- The vector index is content-hashed: only new or changed sections are re-embedded, deleted sections are removed, and model/schema changes rebuild it automatically.
- Dependency-free lexical path: `python wiki/bin/wiki.py search "query" --no-embed`. Semantic search needs `uv` on PATH; without it the launcher fails loudly rather than silently degrading to lexical.

## Graph layer

The wiki has an optional compiled graph layer under `wiki/graph/`:

- `wiki/graph/ontology.yaml` — declares node types and predicates. **Tracked.** Edit this when you introduce new predicates or domain types.
- `wiki/graph/nodes.jsonl`, `wiki/graph/edges.jsonl` — generated. Track in git only if you want graph diffs in PRs.
- `wiki/graph/graph.sqlite` — generated. Gitignored by default.
- `wiki/graph/graph.graphml` — generated. Track only if you want to diff it.

Generation is reproducible from markdown via `python wiki/bin/wiki.py graph-extract`. The graph can be deleted at any time and rebuilt without losing knowledge — markdown is canonical.

## Workflow customizations

- **Script invocation goes through `wiki/bin/wiki.py`.** Never call the plugin's scripts by path, and never call them with bare `python`: bare `python` skips the PEP 723 dependency block, which makes `wiki_search.py` fall back to lexical BM25 with only a warning and makes the graph scripts fail outright on missing PyYAML.
- `/wiki:upgrade` does **not** overwrite this file — `init_wiki.py` skips every file that already exists and only reports which template marker sections are missing, leaving the merge to a human or the agent. The residual hazard is narrower: the plugin's `SCHEMA.md.template` still prints the `skills/llm-wiki/scripts/...` path, which does not exist in this repo, so if a future upgrade asks to merge a **Retrieval** section from the template, that broken path comes with it. Re-point any merged command at `wiki/bin/wiki.py`. Verified against plugin 3.0.0 on 2026-09-01.
- This project is a codebase, not a research corpus. The wiki records durable knowledge about the OAuth/OIDC server — protocol decisions, subsystem contracts, hard-won gotchas. Transient planning artifacts (`TASKS.md`, `specs/`) are deliberately **not** wiki sources: they are scratch files that get deleted, and ingesting them would fill the wiki with claims whose sources vanish.

## User preferences

(Empty initially. As the user expresses style preferences — "always include a 'Why this matters' section on concept pages", "never use bullet lists in summaries", "prefer comparative tables for synthesis pages" — capture them here so they persist across sessions.)

## Lint cadence

- Structural lint: after every 5 ingests.
- Semantic lint: weekly or after every 20 ingests.
- Gap-finding: monthly.
- Graph lint + extract: after every ingest that adds typed `graph.relationships`.

Adjust based on the wiki's growth rate.
