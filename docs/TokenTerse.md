TokenTerse — A Token-Efficient C Philosophy (Humans, AI, and the Compiler)

Goal
Write C that is fast to read, fast to compile, fast to run, and friendly to AI tools.
Terseness is a means, not a goal: shorten only when clarity is preserved.

Core Principles
- Prefer clarity per token: each token should carry meaning and reduce ambiguity.
- Optimize for scan speed: predictable structure beats clever compression.
- Keep invariants obvious: code should say what must be true, not just what happens.
- Bias toward data-driven patterns: fewer branches, more tables.
- Maintain a stable mental model: avoid style drift across files.

Naming & Types
- Use a shared types header: u8/u16/u32/u64, i32, f32, f64, usize, bool.
- Follow the ecosystem: prefer snake_case in C unless the codebase is already camelCase.
- Names short but unambiguous; prefer consistent prefixes over cryptic truncation.
- Use typedefs for repeated compound types: typedef HashMap* HM; when it reduces noise.
- Use enum { N = 64 }; over #define N 64 for scoping and debug visibility.

Macros vs Inline
- Macros only for: compile-time constants, simple wrappers, or codegen tables.
- Prefer static inline for behavior: type-checked, debuggable, optimizer-friendly.
- If a macro is used for a single line, keep it side-effect safe and documented.

Files & Layout
- One file, one concern; split around ~600–1200 lines to keep context small.
- Keep headers minimal: API surface only; implementation stays in .c.
- Arrange functions by call graph: public API at top, helpers below.
- Flatten nesting: early return/continue over deep if/else.

Comments & Documentation
- Names document the "what"; comments explain the "why" and invariants.
- Avoid comments that restate code; add comments for tricky cases or non-obvious tradeoffs.
- Mark ownership and lifetime in comments when not obvious from types.

Config & Tables
- Collapse env/config boilerplate into lookup tables or X-macro lists.
- Prefer tables over repeated branches (better for both CPU and AI pattern matching).

Control Flow & Error Handling
- Keep the fast path straight-line; isolate slow/error paths.
- Return values and error enums should be consistent across a module.
- Prefer explicit error handling over hidden global state.

Compiler & Performance Friendliness
- Avoid undefined behavior; speed gains vanish if correctness is fragile.
- Use const/restrict where valid; they help the optimizer and humans.
- Keep hot structs compact and cache-friendly; separate hot/cold fields.
- Minimize header dependencies; reduce rebuild time and context bloat.

AI Ergonomics
- Maintain consistent idioms so models can infer intent.
- Prefer small, regular APIs over wide, irregular ones.
- Keep interface headers tight to reduce model context size.

Non-goals
- Obfuscation, code golf, or sacrificing correctness.
- Ultra-short identifiers that reduce instant readability.

Philosophy
Much like Richard Feynman distinguished *knowing* from *understanding*,
code should be terse enough that people (and AI) can read it and quickly
understand what it does and why it does it. The goal is superior designs
and earlier detection of bugs and errors.
