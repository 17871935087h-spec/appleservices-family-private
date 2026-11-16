package dashboard

import (
	"context"
	"testing"

	"github.com/Laky-64/appleservices/internal/control"
)

func TestICloudAutomationUpgradesLegacyUnconfirmedRecoveryOnce(t *testing.T) {
	f := newICloudAutomationFixture(t)
	f.accepted = true
	f.status.State = "device_query_failed"
	if err := writeICloudAutomationJournal(f.account, iCloudAutomationJournal{Version: 1, Stage: "resume-unconfirmed", Submitted: true}); err != nil {
		t.Fatal(err)
	}
	f.runOnce(t)
	if f.resumed.Load() != 1 || f.journal(t).RecoveryVersion != 1 {
		t.Fatal("legacy recovery was not upgraded with a bounded attempt")
	}
	f.runOnce(t)
	if f.resumed.Load() != 1 {
		t.Fatal("unconfirmed identity recovery was repeated")
	}
}

func TestICloudAutomationReconcilesLateOnlineRecoveryWithoutRestart(t *testing.T) {
	f := newICloudAutomationFixture(t)
	f.accepted = true
	if err := writeICloudAutomationJournal(f.account, iCloudAutomationJournal{Version: 1, Stage: "resume-unconfirmed", Submitted: true, RecoveryVersion: 1}); err != nil {
		t.Fatal(err)
	}
	f.runOnce(t)
	if f.service.Status(f.account).Stage != "complete" || f.stopped.Load() != 0 || f.resumed.Load() != 0 {
		t.Fatal("late online confirmation was not reconciled without restarting")
	}
}

func TestICloudAutomationUpgradeKeepsVerificationStop(t *testing.T) {
	f := newICloudAutomationFixture(t)
	f.accepted = true
	f.status.State = "verification_required"
	f.status.VerificationRequired = true
	f.resume = func(context.Context, *Account) control.Result {
		t.Fatal("verification stop bypassed")
		return control.Result{}
	}
	if err := writeICloudAutomationJournal(f.account, iCloudAutomationJournal{Version: 1, Stage: "verification-required", Submitted: true}); err != nil {
		t.Fatal(err)
	}
	f.runOnce(t)
	if f.resumed.Load() != 0 {
		t.Fatal("verification-required account was restarted")
	}
}
