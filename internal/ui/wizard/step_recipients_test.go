package wizard

import (
	"strings"
	"testing"

	"filippo.io/age"
)

func TestRecipientsStep_ValidRecipient_ShowsNoError(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	validKey := identity.Recipient().String()

	step := NewRecipientsStep()
	step.input.SetValue(validKey)
	step.validateLive()

	view := step.View()
	if strings.Contains(view, "✗") {
		t.Errorf("View should not contain error marker for valid recipient:\n%s", view)
	}
}

func TestRecipientsStep_InvalidRecipient_ShowsError(t *testing.T) {
	step := NewRecipientsStep()
	step.input.SetValue("age1invalidkey123")
	step.validateLive()

	view := step.View()
	if !strings.Contains(view, "✗") {
		t.Errorf("View should contain error marker for invalid recipient:\n%s", view)
	}
}

func TestRecipientsStep_MixedRecipients_ShowsErrorForInvalidOnly(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	validKey := identity.Recipient().String()

	step := NewRecipientsStep()
	step.input.SetValue(validKey + "\n" + "age1badkey")
	step.validateLive()

	view := step.View()
	if !strings.Contains(view, "✗") {
		t.Errorf("View should contain error marker for mixed recipients:\n%s", view)
	}
	if !strings.Contains(view, "line 2") {
		t.Errorf("View should indicate error on line 2:\n%s", view)
	}
}

func TestRecipientsStep_EmptyInput_ShowsNoError(t *testing.T) {
	step := NewRecipientsStep()
	view := step.View()
	if strings.Contains(view, "✗") {
		t.Errorf("View should not contain error marker for empty input:\n%s", view)
	}
	if !strings.Contains(view, "Ctrl+S to save") {
		t.Errorf("View should show help text for empty input:\n%s", view)
	}
}
