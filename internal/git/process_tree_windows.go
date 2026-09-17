//go:build windows

package git

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsProcessTree struct {
	job windows.Handle
	mu  sync.Mutex
}

var windowsProcessTrees sync.Map // map[*exec.Cmd]*windowsProcessTree

var (
	createJobObject          = windows.CreateJobObject
	setInformationJobObject  = windows.SetInformationJobObject
	assignProcessToJobObject = windows.AssignProcessToJobObject
	terminateJobObject       = windows.TerminateJobObject
)

func configureProcessTree(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED

	job, err := createJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("create job object: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err = setInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		closeErr := windows.CloseHandle(job)
		return errors.Join(fmt.Errorf("configure job object kill on close: %w", err), closeErr)
	}

	windowsProcessTrees.Store(cmd, &windowsProcessTree{job: job})
	return nil
}

func startProcessTree(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return errors.Join(err, closeProcessTree(cmd))
	}

	value, ok := windowsProcessTrees.Load(cmd)
	if !ok {
		return errors.Join(errors.New("process tree setup was lost"), abortStartedProcess(cmd))
	}
	tree := value.(*windowsProcessTree)
	tree.mu.Lock()
	var setupErr error
	if tree.job == 0 {
		setupErr = errors.New("process tree is closed")
	} else {
		var withErr, assignErr error
		withErr = cmd.Process.WithHandle(func(handle uintptr) {
			assignErr = assignProcessToJobObject(tree.job, windows.Handle(handle))
		})
		if withErr != nil {
			setupErr = fmt.Errorf("retrieve process handle for job assignment: %w", withErr)
		} else if assignErr != nil {
			setupErr = fmt.Errorf("assign process to job object: %w", assignErr)
		} else if err := resumePrimaryThread(uint32(cmd.Process.Pid)); err != nil {
			setupErr = fmt.Errorf("resume primary process thread: %w", err)
		}
	}
	tree.mu.Unlock()
	if setupErr != nil {
		return errors.Join(setupErr, abortStartedProcess(cmd))
	}
	return nil
}

func abortStartedProcess(cmd *exec.Cmd) error {
	value, _ := windowsProcessTrees.Load(cmd)
	var terminateErr error
	if value != nil {
		tree := value.(*windowsProcessTree)
		tree.mu.Lock()
		if tree.job != 0 {
			terminateErr = terminateJobObject(tree.job, 1)
		}
		tree.mu.Unlock()
	}
	if cmd.Process != nil {
		killErr := cmd.Process.Kill()
		if errors.Is(killErr, os.ErrProcessDone) {
			killErr = nil
		}
		terminateErr = errors.Join(terminateErr, killErr)
	}
	cmd.WaitDelay = 2 * time.Second
	waitErr := cmd.Wait()
	var exited *exec.ExitError
	if errors.As(waitErr, &exited) {
		waitErr = nil
	}
	return errors.Join(terminateErr, waitErr, closeProcessTree(cmd))
}

func killProcessTree(cmd *exec.Cmd) error {
	value, ok := windowsProcessTrees.Load(cmd)
	if !ok {
		if cmd.Process == nil {
			return nil
		}
		err := cmd.Process.Kill()
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		return err
	}
	tree := value.(*windowsProcessTree)
	tree.mu.Lock()
	defer tree.mu.Unlock()
	if tree.job == 0 {
		windowsProcessTrees.Delete(cmd)
		return nil
	}
	terminateErr := terminateJobObject(tree.job, 1)
	closeErr := windows.CloseHandle(tree.job)
	if closeErr == nil {
		tree.job = 0
		windowsProcessTrees.Delete(cmd)
	}
	return errors.Join(terminateErr, closeErr)
}

func closeProcessTree(cmd *exec.Cmd) error {
	value, ok := windowsProcessTrees.Load(cmd)
	if !ok {
		return nil
	}
	tree := value.(*windowsProcessTree)
	tree.mu.Lock()
	defer tree.mu.Unlock()
	if tree.job == 0 {
		windowsProcessTrees.Delete(cmd)
		return nil
	}
	if err := windows.CloseHandle(tree.job); err != nil {
		return fmt.Errorf("close job object: %w", err)
	}
	tree.job = 0
	windowsProcessTrees.Delete(cmd)
	return nil
}

func resumePrimaryThread(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("create thread snapshot: %w", err)
	}
	closeSnapshot := func() error {
		if err := windows.CloseHandle(snapshot); err != nil {
			return fmt.Errorf("close thread snapshot: %w", err)
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
			thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if err != nil {
				return errors.Join(fmt.Errorf("open primary process thread: %w", err), closeSnapshot())
			}
			previous, resumeErr := windows.ResumeThread(thread)
			closeThreadErr := windows.CloseHandle(thread)
			closeSnapshotErr := closeSnapshot()
			var errs []error
			if resumeErr != nil {
				errs = append(errs, fmt.Errorf("resume primary process thread: %w", resumeErr))
			} else if previous != 1 {
				errs = append(errs, fmt.Errorf("primary process thread had suspend count %d, want 1", previous))
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
