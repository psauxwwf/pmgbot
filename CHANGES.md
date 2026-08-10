# Changes

- Replaced the old deleted-spam sender blacklist/import workflow with daemon-only PMG spam quarantine management.
- Changed one-shot execution to the explicit `pmgbot run --config <file>` command.
- Added `pmgbot check --config <file>` dry-run mode that logs planned deliver/delete actions without applying them.
- Added field-based `deliver` and `delete` regexp rules for `/quarantine/spam` messages.
- Changed quarantine messages to a typed structure and reject unknown rule keys during config validation.
- Changed empty rule keys to be ignored before validation or regexp compilation.
- Removed numeric/internal fields from rule matching; rules now support only `envelope_sender`, `from`, `receiver`, and `subject`.
- Added PMG quarantine actions through `pmgsh create /quarantine/content --id <id> --action deliver|delete`.
- Added rule groups so multiple fields inside one `deliver` or `delete` rule are matched with AND.
- Replaced top-level `deliver`/`delete` rule sections with ordered `rules` containing `name`, `action`, and `when`.
- Added `pmgbot analyze --config <file>` to count repeated spam subjects and show sender counts inside each subject.
