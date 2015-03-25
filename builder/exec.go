package builder

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	ExecTimeout = 15 * time.Minute
)

var (
	timeoutError = errors.New("process timed out")
)

func Exec(cwd string, env map[string]string, command string, args ...string) error {

	// Setup the command and try to start it.
	cmd := exec.Command(command, args...)
	cmd.Dir = cwd

	// Merge the provided environment variables with the environment of this
	// process.
	cmd.Env = os.Environ()
	for key, value := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Have stdout and stderr write to the same buffer.
	output := bytes.NewBuffer([]byte{})
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		return NewExecError(command, args, err, output.String())
	}

	// Make an error channel.
	errSignal := make(chan error)

	// Set a reasonable timeout.
	go func() {
		time.Sleep(ExecTimeout)
		if !cmd.ProcessState.Exited() {
			if err := cmd.Process.Kill(); err != nil {
				errSignal <- NewExecError(command, args, err, output.String())
			} else {
				errSignal <- NewExecError(command, args, timeoutError, output.String())
			}
		}
	}()

	go func() {

		// Wait for the command to exit, one way or another.
		if err := cmd.Wait(); err != nil {
			errSignal <- NewExecError(command, args, err, output.String())
		} else {
			errSignal <- nil
		}
	}()

	if err := <-errSignal; err != nil {
		return err
	}

	return nil
}

func NewExecError(command string, args []string, err error, output string) ExecError {
	return ExecError{
		Command: fmt.Sprintf("%s %q", command, args),
		Err:     err,
		Output:  output,
	}
}

type ExecError struct {
	Command string
	Err     error
	Output  string
}

func (e ExecError) Error() string {
	return e.Err.Error()
}

func (e ExecError) Attatchment() *Attatchment {
	a := NewAttatchment()
	a.Text = fmt.Sprintf("The command *%s* returned an error:\n_%s_\n```\n%s```", e.Command, e.Error(), e.Output)
	a.Color = "danger"
	a.MarkdownIn = []string{"text"}
	return a
}
