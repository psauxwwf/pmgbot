# Changes

- Added configurable `exclude.txt` import filtering for `import` and `daemon`, with daemon rereading exclusions every cycle.
- Changed `exclude.txt` entries to regexp patterns matched against normalized sender emails.
