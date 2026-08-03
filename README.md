# pmgbot

`pmgbot` is a daemon for Proxmox Mail Gateway (PMG) spam quarantine automation.

It reads field-based regexp rules from `pmgbot.yaml`, loads spam quarantine entries through `pmgsh`, and automatically delivers or deletes matching messages.

## How It Works

The daemon runs this cycle:

1. Reads configuration from `pmgbot.yaml`.
2. Gets current spam quarantine entries:

```bash
pmgsh get /quarantine/spam
```

3. Matches every quarantine message against `deliver` rules first.
4. If no deliver rule matches, matches the message against `delete` rules.
5. Applies the selected action by quarantine message ID.
6. Waits for `daemon.every` and repeats the cycle.

If one message matches both `deliver` and `delete`, `deliver` wins.

PMG output may start with `200 OK`; `pmgbot` ignores that prefix before parsing the JSON array.

## Command

Run one cycle and exit:

```bash
pmgbot --config pmgbot.yaml
```

Run continuously as a daemon:

```bash
pmgbot daemon --config pmgbot.yaml
```

Create a default config file:

```bash
pmgbot --save-config --config pmgbot.yaml
```

## Configuration

Example `pmgbot.yaml`:

```yaml
log_level: info
log_path: ""
sudo: true
daemon:
  every: 15m0s
  timeout: 10m0s
deliver:
  envelope_sender:
    - '^trusted@example\.com$'
  from:
    - 'Trusted Sender <trusted@example\.com>'
  subject:
    - '(?i)important report'
delete:
  envelope_sender:
    - '^[^@]+@bad-domain\.ru$'
  from:
    - '(?i)casino|lottery'
  receiver:
    - '^user@example\.com$'
  subject:
    - '(?i)crypto|urgent payment'
```

Fields:

- `log_level`: log level, supports `debug`, `info`, `warn`, and `error`.
- `log_path`: path to a JSON log file; if empty, logs are written only to stderr.
- `sudo`: run external commands through `sudo`.
- `daemon.every`: how often to run the daemon cycle.
- `daemon.timeout`: timeout for each PMG operation phase.
- `deliver`: field-based regexp rules for messages that should be delivered.
- `delete`: field-based regexp rules for messages that should be deleted.

Durations use Go duration syntax, for example `30m`, `1h`, or `10m0s`. A bare number is treated as minutes. `daemon.every` is used only by `pmgbot daemon`; one-shot `pmgbot --config pmgbot.yaml` runs a single cycle immediately and exits.

## Matching Fields

Rule keys must match PMG quarantine JSON field names returned by `/quarantine/spam`:

- `envelope_sender`
- `from`
- `receiver`
- `subject`

Only these text fields are supported for matching. Numeric fields such as `bytes`, `spamlevel`, and `time` are parsed from PMG but are not available as rule keys.

Unknown rule keys are rejected during config validation.

Matching is case-sensitive by default. Use `(?i)` inside a regexp for case-insensitive matching.

## Actions

Deliver a matched message:

```bash
pmgsh create /quarantine/content --id C1R33T82611969 --action deliver
```

Delete a matched message:

```bash
pmgsh create /quarantine/content --id C1R33T82611969 --action delete
```

The `id` is the quarantine API ID returned by `/quarantine/spam`.

## Regexp Examples

### Sender Domains

| What to match                                                | Pattern                              |
| ------------------------------------------------------------ | ------------------------------------ |
| Any direct email at `domain.com`, equivalent to `*@domain.com` | `^[^@]+@domain\.com$`               |
| Any email ending with `@domain.com`                          | `@domain\.com$`                     |
| Any email at `domain.com` or `example.com`                   | `^[^@]+@(domain|example)\.com$`     |
| Any subdomain of `domain.com`, for example `a@sub.domain.com` | `^[^@]+@[^@]+\.domain\.com$`       |
| `domain.com` and any of its subdomains                       | `^[^@]+@([^.@]+\.)*domain\.com$`   |
| Any `.ru` domain                                             | `^[^@]+@[^@]+\.ru$`                 |
| Any `.com` or `.net` domain                                  | `^[^@]+@[^@]+\.(com|net)$`          |

### Specific Emails

| What to match                             | Pattern                         |
| ----------------------------------------- | ------------------------------- |
| Only `email@bob.com`                      | `^email@bob\.com$`             |
| Only `admin@domain.com`                   | `^admin@domain\.com$`          |
| `admin@domain.com` or `support@domain.com` | `^(admin|support)@domain\.com$` |
| Any `no-reply` sender                     | `^no-reply@[^@]+$`              |
| Local part starts with `bounce-`          | `^bounce-[^@]*@[^@]+$`          |
| Local part contains `mailer`              | `^[^@]*mailer[^@]*@[^@]+$`      |

### Subjects

| What to match                     | Pattern                    |
| --------------------------------- | -------------------------- |
| Case-insensitive `invoice`        | `(?i)invoice`              |
| Case-insensitive crypto/lottery   | `(?i)crypto|lottery`       |
| Subject starts with `[SPAM]`      | `^\[SPAM\]`              |

## Build And Test

Build:

```bash
task build
```

Run tests directly:

```bash
go test ./...
```

`task test` in this project runs `go fix ./...` before `go test ./...`.

## Systemd

The repository includes an example `pmgbot.service` unit file.

Expected installation layout:

```text
/opt/pmgbot/pmgbot
/opt/pmgbot/pmgbot.yaml
```

The unit runs:

```bash
/opt/pmgbot/pmgbot daemon --config /opt/pmgbot/pmgbot.yaml
```
