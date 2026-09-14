//go:build windows

package main

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

type windowsProcessGroup struct {
	job windows.Handle
	mu  sync.Mutex
}

var windowsProcessGroups sync.Map // map[*exec.Cmd]*windowsProcessGroup

var createJobObject = windows.CreateJobObject
var setInformationJobObject = windows.SetInformationJobObject
var assignProcessToJobObject = windows.AssignProcessToJobObject
var closeWindowsHandle = windows.CloseHandle

func configureProcessGroup(*exec.Cmd) {}

func startProcessGroup(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED

	job, err := createJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("create job object: %w", err)
	}
	windowsProcessGroups.Store(cmd, &windowsProcessGroup{job: job})
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err = setInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		closeErr := closeProcessGroup(cmd)
		return errors.Join(fmt.Errorf("configure job object kill on close: %w", err), closeErr)
	}

	if err = cmd.Start(); err != nil {
		closeErr := closeProcessGroup(cmd)
		return errors.Join(err, closeErr)
	}
	var withErr error
	var assignErr error
	withErr = cmd.Process.WithHandle(func(handle uintptr) {
		assignErr = assignProcessToJobObject(job, windows.Handle(handle))
	})
	if withErr != nil {
		return errors.Join(fmt.Errorf("retrieve process handle for job assignment: %w", withErr), abortStartedProcess(cmd, job))
	}
	if assignErr != nil {
		return errors.Join(fmt.Errorf("assign process to job object: %w", assignErr), abortStartedProcess(cmd, job))
	}
	if err = resumePrimaryThread(uint32(cmd.Process.Pid)); err != nil {
		return errors.Join(fmt.Errorf("resume suspended oracle: %w", err), abortStartedProcess(cmd, job))
	}
	return nil
}

// A Start success transfers Wait ownership here until job setup succeeds.
// On setup failure the caller does not call Wait, so reap and drain pipes here.
func abortStartedProcess(cmd *exec.Cmd, job windows.Handle) error {
	terminateErr := windows.TerminateJobObject(job, 1)
	killErr := cmd.Process.Kill()
	if errors.Is(killErr, os.ErrProcessDone) {
		killErr = nil
	}
	closeErr := closeProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second
	waitErr := cmd.Wait()
	var exited *exec.ExitError
	if errors.As(waitErr, &exited) {
		waitErr = nil // A killed child is the expected outcome, not a cleanup error.
	}
	return errors.Join(terminateErr, killErr, closeErr, waitErr)
}

func killProcessGroup(cmd *exec.Cmd) (bool, error) {
	value, ok := windowsProcessGroups.Load(cmd)
	if !ok {
		if cmd.Process == nil {
			return false, nil
		}
		if err := cmd.Process.Kill(); err != nil {
			return false, err
		}
		return true, nil
	}
	group := value.(*windowsProcessGroup)
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.job == 0 {
		windowsProcessGroups.Delete(cmd)
		return false, nil
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
	var info windowsJobObjectBasicAccountingInformation
	var terminated bool
	var errs []error
	if err := windows.QueryInformationJobObject(group.job, windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
		errs = append(errs, fmt.Errorf("query job object accounting: %w", err))
	} else if info.ActiveProcesses > 0 {
		if err := windows.TerminateJobObject(group.job, 1); err != nil {
			errs = append(errs, fmt.Errorf("terminate job object: %w", err))
		} else {
			terminated = true
		}
	}
	if err := closeWindowsProcessGroupLocked(cmd, group); err != nil {
		errs = append(errs, fmt.Errorf("close job object on kill: %w", err))
	}
	return terminated, errors.Join(errs...)
}

func closeProcessGroup(cmd *exec.Cmd) error {
	value, ok := windowsProcessGroups.Load(cmd)
	if !ok {
		return nil
	}
	group := value.(*windowsProcessGroup)
	group.mu.Lock()
	defer group.mu.Unlock()
	return closeWindowsProcessGroupLocked(cmd, group)
}

func closeWindowsProcessGroupLocked(cmd *exec.Cmd, group *windowsProcessGroup) error {
	if group.job == 0 {
		windowsProcessGroups.Delete(cmd)
		return nil
	}
	if err := closeWindowsHandle(group.job); err != nil {
		return fmt.Errorf("close job object: %w", err)
	}
	group.job = 0
	windowsProcessGroups.Delete(cmd)
	return nil
}

var resumePrimaryThread = resumePrimaryThreadImpl

func resumePrimaryThreadImpl(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err = windows.Thread32First(snapshot, &entry); err != nil {
		return err
	}
	for {
		if entry.OwnerProcessID == pid {
			thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if err != nil {
				return err
			}
			previous, resumeErr := windows.ResumeThread(thread)
			closeErr := windows.CloseHandle(thread)
			if resumeErr != nil {
				return resumeErr
			}
			if closeErr != nil {
				return closeErr
			}
			if previous == 0 {
				return errors.New("primary process thread was not suspended")
			}
			return nil
		}
		if err = windows.Thread32Next(snapshot, &entry); err != nil {
			return err
		}
	}
}
