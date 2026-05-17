# Local Development Guide

No Docker required. Hearth ships with a built-in **mailcatcher** transport that
captures every outbound email in-process and serves them in a browser UI.

---

## Quick start

```bash
# One-time setup
make setup            # enables repo git hooks
make tailwind-install # downloads Tailwind CLI (needed for CSS changes only)

# Start the dev server
make dev              # = cargo run -- serve --dev
```

The server binds to `http://127.0.0.1:8420` with in-memory storage and the
built-in mailcatcher active. Open the setup URL logged at startup to create
your first admin account.

---

## Email in dev mode

`--dev` auto-enables the **mailcatcher** transport. All outbound emails
(verification links, password resets, magic links, setup notifications) are
captured in-process instead of being sent over SMTP.

On startup the terminal prints:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  MailcatcherSender active
  Inbox:    http://127.0.0.1:8420/dev/mail
  Password: <random 16-char password>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Open `http://127.0.0.1:8420/dev/mail` in your browser, enter the password, and
you will see a list of all captured emails. Click any email to view its full
HTML body with working, clickable links (links open in a new tab).

The inbox holds the last 50 emails. It resets when the server restarts.

### Transport selection rules

| Config `email.transport` | `--dev` behaviour |
|--------------------------|-------------------|
| `log` (default)          | Upgraded to `mailcatcher` silently |
| `smtp`                   | Upgraded to `mailcatcher` + startup warning |
| `mailcatcher`            | Used as-is |
| `sendgrid` / `postmark` / `mailgun` / `mailtrap` | Kept unchanged (intentional — test against real provider) |

The warning for SMTP override looks like:

```
WARN dev mode: overriding smtp transport → mailcatcher (no Docker required);
     set email.transport = mailcatcher explicitly to silence this warning
```

To silence it, add `email.transport: mailcatcher` to your `hearth.yaml` (or
remove the smtp block entirely).

---

## First-run setup flow

After `make dev`, the server logs a one-time setup URL:

```
WARN first-run setup required: open this URL to create the initial admin account
     setup_url=http://localhost:8420/ui/setup?token=<token>
```

Open that URL. The setup wizard will:
1. Ask for your admin email and password.
2. Send a **verification email** to the mailcatcher inbox.
3. Open `http://127.0.0.1:8420/dev/mail`, click the email, then click
   **"Complete Setup"** to activate your account.

The setup token is single-use and stored in `$TMPDIR/hearth-dev-onboarding/.setup_token`.

---

## Development commands

| Command | What it does |
|---------|-------------|
| `make dev` | Start dev server (mailcatcher, in-memory storage) |
| `make check` | clippy + fmt + nextest — run before every PR |
| `make test` | `cargo nextest run --workspace` |
| `make css` | Rebuild Tailwind CSS (needed after template changes) |
| `bacon test` | TDD watch loop |

---

## Persistent dev storage

`--dev` uses in-memory storage that resets on restart. For a persistent local
instance (e.g. testing migrations or config reconciliation), run with a config
file instead:

```bash
cp hearth.example.yaml hearth.yaml
# edit hearth.yaml: set storage.data_dir, oidc.issuer
cargo run -- serve -c hearth.yaml
```

In this mode `--dev` is not used, so the mailcatcher is not auto-enabled. Add
`email.transport: mailcatcher` to `hearth.yaml` if you still want in-process
email capture without a real SMTP server.

---

## Production deployment

Container images, systemd units, and Helm charts live in [`deploy/`](../../deploy/).
See [`deploy/README.md`](../../deploy/README.md) for deployment instructions.
