package cmd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"
)

type Cmd struct {
	ctx    context.Context
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

var ErrTimeout = errors.New("timeout")

var useSudo bool

func SetSudo(enabled bool) {
	useSudo = enabled
}

func New(command string, args []string, timeout time.Duration, envs ...string) (*Cmd, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return newCmd(ctx, cancel, command, args, envs...)
}

func NewContext(ctx context.Context, command string, args []string, envs ...string) (*Cmd, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(ctx)
	return newCmd(ctx, cancel, command, args, envs...)
}

func newCmd(ctx context.Context, cancel context.CancelFunc, command string, args []string, envs ...string) (*Cmd, context.CancelFunc, error) {
	if useSudo {
		args = append([]string{command}, args...)
		command = "sudo"
	}
	execCmd := exec.CommandContext(ctx, command, args...)
	execCmd.Env = append(os.Environ(), envs...)

	return &Cmd{
		ctx:    ctx,
		cmd:    execCmd,
		cancel: cancel,
	}, cancel, nil
}

func (cmd *Cmd) Run() ([]byte, error) {
	defer cmd.cancel()

	out, err := cmd.cmd.CombinedOutput()
	if err != nil {
		if errors.Is(cmd.ctx.Err(), context.DeadlineExceeded) {
			return out, ErrTimeout
		}
		return out, err
	}
	return out, nil
}
