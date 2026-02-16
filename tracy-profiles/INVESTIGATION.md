# Project Diff Split View Scrolling Performance Investigation

## Problem
Scrolling is extremely laggy in Zed's **project diff split view** on Linux when opening a large git repo (chromium with `git reset HEAD~1000`). macOS eventually "catches up" but Linux never does.

## Root Cause
`ProjectDiff::refresh()` (`crates/git_ui/src/project_diff.rs`) runs continuously on the foreground thread, loading buffers and calling `register_buffer()` for each one. This modifies the multibuffer (via `set_excerpts_for_path`), invalidating the display map. Each subsequent `DisplayMap::snapshot()` call must sync fold→tab→wrap→block maps for **both** editors in the split view. Additionally, `fold_buffer()` calls inside `register_buffer` for deleted/untracked files trigger full display map syncs costing 80-130ms each.

## Changes Made

### Commit 1: Reduce redundant snapshot calls
1. **`crates/editor/src/highlight_matching_bracket.rs`**: `refresh_matching_bracket_highlights` now takes `&DisplaySnapshot` instead of `&Window`, eliminating its internal `self.snapshot()` call.
2. **`crates/editor/src/editor.rs` (`selections_did_change`)**: Reuses existing `display_map` variable instead of calling `self.snapshot()`.
3. **`crates/editor/src/editor.rs` (`on_buffer_event` Edited handler)**: Removed `snapshot()`, `refresh_matching_bracket_highlights()`, and `refresh_sticky_headers()` calls entirely. Bracket highlights are already refreshed via `selections_did_change`; sticky headers early-return for multibuffers.

### Commit 2: Scroll throttle + fold batching

#### Scroll throttle (`crates/git_ui/src/project_diff.rs`)
- Added `is_scrolling: bool` and `_scroll_debounce_task: Option<Task<()>>` fields to `ProjectDiff`.
- `handle_editor_event` now handles `EditorEvent::ScrollPositionChanged { local: true }`: sets `is_scrolling = true` and starts a 150ms debounce task to reset it.
- `refresh()` loop checks `is_scrolling` before each `register_buffer()` call and waits in 50ms intervals while true.
- Prevents 2-16ms per-buffer `register_buffer` overhead from accumulating during active scrolling.

#### Fold batching (`crates/editor/src/editor.rs`, `crates/git_ui/src/project_diff.rs`, `crates/git_ui/src/commit_view.rs`)
- Added `Editor::fold_buffers_batch()` that folds multiple buffers in a **single display map sync** instead of N individual syncs. Each individual sync was 80-130ms in split view because it syncs both editors' fold→tab→wrap→block maps.
- Changed `register_buffer()` to return `Option<BufferId>` for deferred folding instead of folding inline.
- `refresh()` loop collects buffer IDs that need folding and calls `fold_buffers_batch` once after the loop.
- Also applied batching to `Editor::fold()`, `Editor::fold_all()`, and `CommitView` which had the same per-buffer loop pattern.

## Profile Results

### Commit 1 impact (run1 baseline → fix2)

| Metric | run1 (baseline) | fix2 (after commit 1) |
|--------|----------------|----------------------|
| `snapshot` calls | 26,032 | 8,057 |
| `snapshot` total time | 95.1s | 25.1s |
| `refresh_matching_bracket_highlights` | 54.4s / 1800 calls | 0.1s / 62 calls |
| `block_map::read` | 86.6s / 79K calls | 23.6s / 23K calls |

### Commit 2 impact (fix3/fix4)
- Fold batching eliminates N × 80-130ms individual `fold_buffer` syncs, replacing with 1 batch sync.
- Scroll throttle prevents `register_buffer` from running during active scrolling.
- **Important**: Tracy instrumentation overhead significantly inflates measurements on hot paths (millions of spans/sec on foreground thread). Without Tracy, the improvement is clearly perceivable — scrolling feels much better.

### Key profile finding: rendering is smooth when refresh is idle
From fix3 profile, during t=78-91s (zero `register_buffer` activity):
- **Maximum foreground operation: 4.6ms** — perfectly smooth rendering
- Zero operations >5ms
- `snapshot` avg 0.07ms, `chunks_at` avg 0.255ms — normal cost

All lag correlated with `register_buffer` activity, specifically `fold_buffers` calls.

## Key Files
- **`crates/git_ui/src/project_diff.rs`**: `refresh()`, `register_buffer()`, scroll throttle
- **`crates/editor/src/editor.rs`**: `fold_buffer()`, `fold_buffers_batch()`, `on_buffer_event()`, `selections_did_change()`
- **`crates/editor/src/highlight_matching_bracket.rs`**: `refresh_matching_bracket_highlights()`
- **`crates/editor/src/display_map.rs`**: `snapshot()`, `fold_buffers()`, `with_synced_companion_mut()`
- **`crates/editor/src/display_map/block_map.rs`**: `fold_or_unfold_buffers()`, `sync()`
- **`crates/editor/src/split.rs`**: `SplittableEditor`, event forwarding
- **`crates/git_ui/src/commit_view.rs`**: fold batching applied here too

## Profiling Setup
```
RUSTFLAGS="-C force-frame-pointers=yes -C force-unwind-tables=yes" ZTRACING=1 cargo build --workspace --profile release-fast --features tracy
tracy-capture -a 127.0.0.1 -p 8086 -o run.tracy
tracy-csvexport [-e] [-u] run.tracy > output.csv
```
Note: Tracy overhead is substantial on hot paths (millions of `ztracing` spans/sec). Profile timings are inflated vs production. Always verify perceived performance without Tracy.

## Potential Further Improvements
1. **Batch `set_excerpts_for_path` calls**: Currently each buffer registration modifies the multibuffer individually. Batching multiple excerpt insertions could reduce cascading display map invalidations.
2. **Move tree-sitter reparsing off foreground thread**: `reparse` self-time was 24% in profiles, though mostly on background threads already.
3. **Reduce snapshot calls per frame in split view**: Some frames had 50-100+ snapshot calls. The rendering path in `EditorElement::prepaint` takes one snapshot, but other code paths (sticky headers, scroll position, etc.) take additional ones.
4. **Profile without Tracy** to get accurate wall-clock timings for remaining bottlenecks.