//go:build windows

package diff

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsProcessTreeState uint8

const (
	windowsProcessTreeReady windowsProcessTreeState = iota
	windowsProcessTreeAssigned
	windowsProcessTreeResumed
	windowsProcessTreeClosed
)

type windowsProcessTree struct {
	cmd   *exec.Cmd
	job   windows.Handle
	state windowsProcessTreeState
	mu    sync.Mutex
}

func newProcessTree(cmd *exec.Cmd) (processTree, error) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create job object: %w", err)
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		closeErr := windows.CloseHandle(job)
		if closeErr != nil {
			return nil, errors.Join(
				fmt.Errorf("configure job object kill on close: %w", err),
				fmt.Errorf("close job object after configuration failure: %w", closeErr),
			)
		}
		return nil, fmt.Errorf("configure job object kill on close: %w", err)
	}

	return &windowsProcessTree{cmd: cmd, job: job}, nil
}

// Assign admits the suspended process to the job, then resumes its primary
// thread. Keeping both operations in this lifecycle step prevents descendants
// from running before they inherit the job membership.
func (t *windowsProcessTree) Assign() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch t.state {
	case windowsProcessTreeAssigned, windowsProcessTreeResumed:
		return errors.New("process tree already assigned")
	case windowsProcessTreeClosed:
		return errors.New("process tree is closed")
	}
	if t.cmd.Process == nil {
		return errors.New("cannot assign nil process to job object")
	}

	var assignErr error
	withErr := t.cmd.Process.WithHandle(func(handle uintptr) {
		assignErr = windows.AssignProcessToJobObject(t.job, windows.Handle(handle))
	})
	if withErr != nil {
		return fmt.Errorf("retrieve process handle for job assignment: %w", withErr)
	}
	if assignErr != nil {
		return fmt.Errorf("assign process to job object: %w", assignErr)
	}
	t.state = windowsProcessTreeAssigned

	if err := resumePrimaryThread(uint32(t.cmd.Process.Pid)); err != nil {
		return fmt.Errorf("resume primary process thread: %w", err)
	}
	t.state = windowsProcessTreeResumed
	return nil
}

func resumePrimaryThread(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("create thread snapshot: %w", err)
	}

	closeSnapshot := func() error {
		if closeErr := windows.CloseHandle(snapshot); closeErr != nil {
			return fmt.Errorf("close thread snapshot: %w", closeErr)
		}
		return nil
	}

	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Thread32First(snapshot, &entry); err != nil {
		return errors.Join(fmt.Errorf("enumerate process threads: %w", err), closeSnapshot())
	}

	for {
		if entry.OwnerProcessID == pid {
			thread, openErr := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if openErr != nil {
				return errors.Join(
					fmt.Errorf("open primary process thread: %w", openErr),
					closeSnapshot(),
				)
			}

			previousSuspendCount, resumeErr := windows.ResumeThread(thread)
			closeThreadErr := windows.CloseHandle(thread)
			closeSnapshotErr := closeSnapshot()
			var errs []error
			if resumeErr != nil {
				errs = append(errs, fmt.Errorf("resume primary process thread: %w", resumeErr))
			} else if previousSuspendCount == 0 {
				errs = append(errs, errors.New("primary process thread was not suspended"))
			}
			if closeThreadErr != nil {
				errs = append(errs, fmt.Errorf("close primary process thread: %w", closeThreadErr))
			}
			if closeSnapshotErr != nil {
				errs = append(errs, closeSnapshotErr)
			}
			return errors.Join(errs...)
		}

		if err := windows.Thread32Next(snapshot, &entry); err != nil {
			return errors.Join(fmt.Errorf("enumerate process threads: %w", err), closeSnapshot())
		}
	}
}

type windowsJobObjectBasicAccountingInformation struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

func (t *windowsProcessTree) activeProcessesLocked() (uint32, error) {
	var info windowsJobObjectBasicAccountingInformation
	if err := windows.QueryInformationJobObject(
		t.job,
		windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		nil,
	); err != nil {
		return 0, fmt.Errorf("query job object accounting: %w", err)
	}
	return info.ActiveProcesses, nil
}

func (t *windowsProcessTree) Kill() (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state == windowsProcessTreeClosed {
		return false, nil
	}

	activeProcesses, queryErr := t.activeProcessesLocked()
	var errs []error
	if queryErr != nil {
		errs = append(errs, queryErr)
	} else if activeProcesses > 0 {
		if err := windows.TerminateJobObject(t.job, 1); err != nil {
			errs = append(errs, fmt.Errorf("terminate job object: %w", err))
		}
	}
	if err := t.closeLocked(); err != nil {
		errs = append(errs, fmt.Errorf("close job object on kill: %w", err))
	}
	return queryErr == nil && activeProcesses > 0, errors.Join(errs...)
}

func (t *windowsProcessTree) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeLocked()
}

func (t *windowsProcessTree) closeLocked() error {
	if t.state == windowsProcessTreeClosed {
		return nil
	}
	if err := windows.CloseHandle(t.job); err != nil {
		return fmt.Errorf("close job object: %w", err)
	}
	t.job = 0
	t.state = windowsProcessTreeClosed
	return nil
}
