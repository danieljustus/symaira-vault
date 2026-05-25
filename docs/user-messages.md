# Symaira Vault user-message style guide

User-facing strings — prompts, error messages, hints — are part of the
product. They should help the user understand what happened and what to
do next. This guide describes the conventions we follow.

## Audience

Assume a user who:
- knows their way around a terminal
- may not yet understand Symaira Vault internals
- wants the next concrete action, not a Go stack trace

## Principles

1. **Tell the user what happened, in their words.**
   - Bad: `read password: EOF`
   - Good: `Could not read passphrase — input ended before you finished typing.`

2. **Suggest the next action when one is obvious.**
   - Bad: `vault locked`
   - Good: `Vault is locked. Run 'openpass unlock' or set OPENPASS_PASSPHRASE.`

3. **Quote commands so they're copyable.**
   - Bad: `try openpass init first`
   - Good: ``Run `openpass init` first.``

4. **Don't shout. Don't apologize. Don't blame the user.**
   - Bad: `ERROR: INVALID PASSPHRASE!!!`
   - Bad: `Sorry, something went wrong on our end.`
   - Good: `Passphrase did not match. Try again or use 'openpass auth status'.`

5. **One sentence per finding, lower-case verbs after the colon.**
   - Bad: `Cannot Open Vault: Permission Denied.`
   - Good: `cannot open vault: permission denied`
   (Go convention: error strings are lowercase, no trailing punctuation.)

6. **Error wrap context belongs in `%w`, not duplicated in the message.**
   - Bad: `fmt.Errorf("read passphrase: read passphrase: %w", err)`
   - Good: `fmt.Errorf("read passphrase: %w", err)`

## Where each kind of message goes

| Kind            | Channel | Color           | Examples |
|-----------------|---------|-----------------|----------|
| Hard error      | stderr  | red             | `cliout.Errorf(...)` |
| Warning         | stderr  | yellow          | `cliout.Warnf(...)` |
| Hint / nudge    | stderr  | green           | `cliout.Hintf(...)` |
| Normal output   | stdout  | none / theme    | `cmd.Println` or `PrintResult` |
| Prompt          | stderr  | none            | `fmt.Fprint(os.Stderr, ...)` |

Reasoning: stdout is for "the thing the user asked for" (parseable, pipeable);
stderr is for everything else (status, errors, prompts), so `openpass get x.password | xclip`
still works.

## Tone

- Plain English. No marketing language ("magical experience", "seamless").
- No emoji in prompts. Symbols come from `internal/ui/theme.Symbol*` and
  fall back to ASCII when the terminal/locale demands it.
- It is OK to refer to a feature by its CLI name (`'openpass doctor'`,
  `--no-pipe-warning`) — those are the user's hooks back into the tool.

## Localization

User-facing strings should be small, parameterized phrases — short enough to
translate without breaking layout (TTY box-drawing). Avoid concatenation
across multiple sprintfs that an i18n catalog cannot recombine in another
language.

The i18n framework (audit issue H1) is tracked separately; today everything
is English.

## Checklist for new messages

Before merging a PR that adds a new user-facing string:

- [ ] Reads naturally if pasted into a chat window.
- [ ] Names a concrete next action (or none — but don't trail off).
- [ ] Goes to the right channel (stdout vs stderr) and uses the matching
      cliout helper for color.
- [ ] No trailing `!`, no all-caps, no `Sorry, ...`.
- [ ] Commands and flags are quoted in backticks.
