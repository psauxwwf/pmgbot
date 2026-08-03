# Changes

- Replaced the old deleted-spam sender blacklist/import workflow with daemon-only PMG spam quarantine management.
- Changed root `pmgbot --config <file>` execution to run one quarantine cycle and exit.
- Added field-based `deliver` and `delete` regexp rules for `/quarantine/spam` messages.
- Changed quarantine messages to a typed structure and reject unknown rule keys during config validation.
- Changed empty rule keys to be ignored before validation or regexp compilation.
- Removed numeric/internal fields from rule matching; rules now support only `envelope_sender`, `from`, `receiver`, and `subject`.
- Added PMG quarantine actions through `pmgsh create /quarantine/content --id <id> --action deliver|delete`.
