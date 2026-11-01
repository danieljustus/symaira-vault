//! State-machine tests for the interactive `add` form. Expected values mirror
//! what the Go oracle (`internal/ui/forms/add_form.go`) produced in the PTY
//! differential recorded for this port.
#![allow(dead_code)]

#[path = "../src/add_form.rs"]
mod add_form;

use std::time::{Duration, Instant};

use add_form::{AddForm, Flow, FormDefaults, FormResult};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::{Value, json};

const STRONG: &str = "Xk9#mP2$vL7qZ!aaBB";

struct Driver {
    form: AddForm,
    now: Instant,
}

impl Driver {
    fn new(force: bool) -> Self {
        let now = Instant::now();
        let mut form = AddForm::new(force);
        form.start(now);
        Self { form, now }
    }

    fn with_defaults(force: bool, defaults: &FormDefaults) -> Self {
        let mut driver = Self::new(force);
        driver.form.set_defaults(defaults);
        driver
    }

    /// Types text as one terminal read (one Bubble Tea message).
    fn paste(&mut self, text: &str) -> Flow {
        let runes: Vec<char> = text.chars().collect();
        self.form.text(&runes, self.now)
    }

    /// Types text one key press at a time.
    fn type_slowly(&mut self, text: &str) {
        for c in text.chars() {
            self.key(KeyCode::Char(c), KeyModifiers::NONE);
        }
    }

    fn key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Flow {
        self.form.key(&KeyEvent::new(code, modifiers), self.now)
    }

    fn press(&mut self, code: KeyCode) -> Flow {
        self.key(code, KeyModifiers::NONE)
    }

    fn tab(&mut self, times: usize) {
        for _ in 0..times {
            self.press(KeyCode::Tab);
        }
    }

    fn ctrl(&mut self, c: char) -> Flow {
        self.key(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn advance(&mut self, by: Duration) {
        self.now += by;
        self.form.run_due_ticks(self.now);
    }

    fn result(&self) -> FormResult {
        self.form.result()
    }
}

fn string(value: &str) -> Value {
    Value::String(value.to_owned())
}

#[test]
fn password_autodetects_type_and_usage_hint_from_the_whole_pasted_run() {
    let mut form = Driver::new(false);
    form.tab(1);
    form.paste(&format!("ghp_{}", "a".repeat(36)));
    let result = form.result();
    assert_eq!(result.secret_type, "bearer_token");
    assert_eq!(
        result.usage_hint,
        "Set Header Authorization: Bearer <token>"
    );
}

#[test]
fn first_typed_character_fixes_the_detected_type() {
    // Typed one key at a time the type is detected from "g" (password) and
    // sticks, exactly like the Go form.
    let mut form = Driver::new(false);
    form.tab(1);
    form.type_slowly(&format!("ghp_{}", "a".repeat(36)));
    assert_eq!(form.result().secret_type, "password");
}

#[test]
fn explicit_type_is_not_overridden_and_normalised() {
    let mut form = Driver::new(false);
    form.tab(1);
    form.paste(STRONG);
    form.tab(1);
    form.ctrl('u');
    form.paste("API_Key");
    let result = form.result();
    assert_eq!(result.secret_type, "api_key");
    // The hint set while the type was "password" stays; only blank hints refresh.
    assert!(result.usage_hint.starts_with("Use for authentication"));
}

#[test]
fn unknown_type_text_becomes_custom() {
    let mut form = Driver::new(false);
    form.tab(2);
    form.paste("zzz");
    let result = form.result();
    assert_eq!(result.secret_type, "custom");
    assert_eq!(
        result.usage_hint,
        "Follow the specific integration instructions for this secret."
    );
}

#[test]
fn enter_moves_forward_and_last_enter_submits() {
    let mut form = Driver::new(false);
    form.paste("alice");
    assert_eq!(form.press(KeyCode::Enter), Flow::Continue);
    assert_eq!(form.form.focused_field(), 1);
    form.paste(STRONG);
    form.press(KeyCode::Enter);
    form.press(KeyCode::Enter);
    // Usage hint is a textarea: Enter inserts a newline instead of moving on.
    assert_eq!(form.form.focused_field(), 3);
    form.press(KeyCode::Enter);
    assert_eq!(form.form.focused_field(), 3);
    form.tab(6);
    assert_eq!(form.form.focused_field(), 9);
    assert_eq!(form.press(KeyCode::Enter), Flow::Submit);
}

#[test]
fn backspace_on_empty_field_returns_to_previous_field() {
    let mut form = Driver::new(false);
    form.paste("ab");
    form.tab(1);
    assert_eq!(form.form.focused_field(), 1);
    form.press(KeyCode::Backspace);
    assert_eq!(form.form.focused_field(), 0);
    form.press(KeyCode::Backspace);
    assert_eq!(form.result().data.get("username"), Some(&string("a")));
    // First field never goes below zero.
    form.press(KeyCode::Backspace);
    form.press(KeyCode::Backspace);
    form.press(KeyCode::Backspace);
    assert_eq!(form.form.focused_field(), 0);
}

#[test]
fn ctrl_c_cancels_and_escape_is_ignored() {
    let mut form = Driver::new(false);
    assert_eq!(form.press(KeyCode::Esc), Flow::Continue);
    form.paste("abc");
    assert_eq!(form.result().data.get("username"), Some(&string("abc")));
    assert_eq!(form.ctrl('c'), Flow::Cancel);
    assert!(form.form.canceled());
}

#[test]
fn weak_password_is_advisory_and_force_hides_the_warning() {
    let mut weak = Driver::new(false);
    weak.tab(1);
    weak.paste("weak");
    let view = weak.form.view(weak.now).join("\n");
    assert!(view.contains("password too short"), "{view}");
    assert_eq!(
        weak.result().data.get("password"),
        Some(&string("weak")),
        "weak passwords still submit"
    );

    let mut forced = Driver::new(true);
    forced.tab(1);
    forced.paste("weak");
    let view = forced.form.view(forced.now).join("\n");
    assert!(view.contains("Strength: OK"), "{view}");
    assert!(!view.contains("password too short"));

    let mut strong = Driver::new(false);
    strong.tab(1);
    strong.paste(STRONG);
    assert!(
        strong
            .form
            .view(strong.now)
            .join("\n")
            .contains("Strength: OK")
    );
}

#[test]
fn data_is_trimmed_and_totp_extras_need_a_secret() {
    let mut form = Driver::new(false);
    form.paste("  spaced  ");
    form.tab(1);
    form.paste(STRONG);
    form.tab(4);
    form.paste("  https://t.example  ");
    form.tab(1);
    form.paste("  ");
    form.press(KeyCode::Enter);
    form.paste("  note  ");
    form.press(KeyCode::Enter);
    form.paste(" ");
    form.tab(1);
    form.paste("   ");
    form.tab(1);
    form.paste(" Iss ");
    form.tab(1);
    form.paste(" Acct ");
    let data = form.result().data;
    assert_eq!(data["username"], string("spaced"));
    assert_eq!(data["url"], string("https://t.example"));
    assert_eq!(data["notes"], string("note"));
    assert!(
        !data.contains_key("totp"),
        "blank TOTP secret drops issuer/account: {data:?}"
    );

    let mut form = Driver::new(false);
    form.tab(7);
    form.paste(" JBSWY3DPEHPK3PXPJBSWY3DPEH ");
    form.tab(1);
    form.paste(" Iss ");
    form.tab(1);
    form.paste(" Acct ");
    assert_eq!(
        form.result().data["totp"],
        json!({"secret": "JBSWY3DPEHPK3PXPJBSWY3DPEH", "issuer": "Iss", "account_name": "Acct"})
    );
}

#[test]
fn empty_form_yields_empty_data_and_no_type() {
    let result = Driver::new(false).result();
    assert!(result.data.is_empty());
    assert_eq!(result.secret_type, "");
    assert_eq!(result.usage_hint, "");
    assert!(!result.auto_rotate);
}

#[test]
fn auto_rotate_is_true_only_for_exact_yes() {
    for (text, expected) in [("yes", true), ("YES", false), ("y", false), ("no", false)] {
        let mut form = Driver::new(false);
        form.tab(4);
        form.ctrl('u');
        form.paste(text);
        assert_eq!(form.result().auto_rotate, expected, "{text}");
    }
}

#[test]
fn defaults_prefill_fields_like_build_form_defaults() {
    let form = Driver::with_defaults(
        false,
        &FormDefaults {
            username: "u1".into(),
            url: "https://f.example".into(),
            notes: "fn".into(),
            secret_type: "API_KEY".into(),
            usage_hint: String::new(),
            auto_rotate: true,
            totp_secret: "JBSWY3DPEHPK3PXPJBSWY3DPEH".into(),
            totp_issuer: "FI".into(),
            totp_account: "FA".into(),
        },
    );
    let result = form.result();
    assert_eq!(result.data["username"], string("u1"));
    assert_eq!(result.data["url"], string("https://f.example"));
    assert_eq!(result.data["notes"], string("fn"));
    assert_eq!(
        result.data["totp"],
        json!({"secret": "JBSWY3DPEHPK3PXPJBSWY3DPEH", "issuer": "FI", "account_name": "FA"})
    );
    assert_eq!(result.secret_type, "api_key");
    assert!(
        result
            .usage_hint
            .starts_with("Set as header or query parameter")
    );
    assert!(result.auto_rotate);
    assert!(!result.data.contains_key("password"));
}

#[test]
fn explicit_usage_hint_default_wins_over_type_hint() {
    let form = Driver::with_defaults(
        false,
        &FormDefaults {
            secret_type: "ssh_key".into(),
            usage_hint: "FLAGHINT".into(),
            ..FormDefaults::default()
        },
    );
    assert_eq!(form.result().usage_hint, "FLAGHINT");
    assert_eq!(form.result().secret_type, "ssh_key");
}

#[test]
fn stray_blink_tick_refreshes_blank_usage_hint_on_type_field() {
    // Go routes every message (including cursor-blink ticks) to the focused
    // widget; on the type field that re-derives a blank usage hint.
    let mut form = Driver::new(false);
    form.tab(2);
    assert_eq!(form.result().usage_hint, "");
    form.advance(Duration::from_millis(600));
    assert_eq!(
        form.result().usage_hint,
        "Follow the specific integration instructions for this secret."
    );
    assert_eq!(form.result().secret_type, "");
}

#[test]
fn textarea_keeps_newlines_and_honours_editing_keys() {
    let mut form = Driver::new(false);
    form.tab(6);
    form.paste("l1");
    form.press(KeyCode::Enter);
    form.paste("l2");
    form.press(KeyCode::Enter);
    form.paste("l3");
    form.press(KeyCode::Up);
    form.press(KeyCode::Up);
    form.ctrl('a');
    form.ctrl('d');
    form.ctrl('d');
    assert_eq!(form.result().data["notes"], string("l2\nl3"));
    // Ctrl+K at end of a line joins the next line.
    form.ctrl('e');
    form.ctrl('k');
    assert_eq!(form.result().data["notes"], string("l2l3"));
}

#[test]
fn single_line_inputs_replace_newlines_and_respect_char_limits() {
    let mut form = Driver::new(false);
    form.paste("a\nb\tc");
    assert_eq!(form.result().data["username"], string("a b c"));

    let mut form = Driver::new(false);
    form.paste(&"u".repeat(300));
    match &form.result().data["username"] {
        Value::String(name) => assert_eq!(name.len(), 256),
        other => panic!("{other:?}"),
    }
}

#[test]
fn text_runs_named_like_keys_trigger_the_binding_as_in_go() {
    // Bubble Tea names a KeyRunes message by its text, so pasting exactly
    // "tab" is indistinguishable from the Tab key.
    let mut form = Driver::new(false);
    form.paste("tab");
    assert_eq!(form.form.focused_field(), 1);
    assert!(form.result().data.is_empty());
}

#[test]
fn word_and_line_editing_in_single_line_inputs() {
    let mut form = Driver::new(false);
    form.paste("foo bar baz");
    form.ctrl('w');
    assert_eq!(form.result().data["username"], string("foo bar"));
    form.ctrl('a');
    form.ctrl('k');
    assert!(form.result().data.is_empty());
    form.paste("abc def");
    form.key(KeyCode::Left, KeyModifiers::NONE);
    form.key(KeyCode::Left, KeyModifiers::NONE);
    form.key(KeyCode::Char('d'), KeyModifiers::CONTROL);
    assert_eq!(form.result().data["username"], string("abc df"));
}
