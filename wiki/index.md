# Wiki Index

The catalog of all pages in this wiki. Each entry: a wikilink to the page and a one-line summary. The LLM reads this first when answering queries to identify candidate pages.

Keep summaries tight — one line each. The index is engineered to be cheap to read; a fat index defeats its purpose.

When this file exceeds ~300 lines or the wiki passes ~150 pages, shard into `wiki/indexes/<type>.md` and replace this file with a directory of shards. See the `scaling-playbook.md` reference in the `llm-wiki` skill for the migration procedure.

---

## Sources

- [[oauth-server-codebase]] — the tracked `lib/` source tree, read at commit `2125ad0`; the source of record for every page below.

## Entities

- [[event-bus]] — the lifecycle `EventEmitter` that used to be the provider; a leaf module that must import no model, and imports the key store for its side effect.

## Concepts

- [[account-resolution]] — `findAccount` is a direct-import DB resolver, not a config option; enforces active status at every resolution and merges claims from the user record.
- [[client-identity-from-database]] — `adapter('Client')` is the single source of client identity; the adapter is read every call and the LRU memo caches only validated objects, keyed by property hash.
- [[feature-flag-gating]] — flat dotted keys on `ApplicationConfig`, boot-only derived `configuration`, and the `onRequest` gate that makes a disabled endpoint answer as unserved.
- [[token-payload-access-contract]] — model state lives under `.payload.*`; reading a bare field yields `undefined` silently, and payload schemas are composed per token type.

## Synthesis

(populated as query answers are filed back)
