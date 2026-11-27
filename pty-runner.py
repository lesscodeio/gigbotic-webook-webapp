#!/usr/bin/env python3
import fcntl, os, pty, select, signal, struct, sys, termios

if len(sys.argv) < 2:
    sys.exit(2)

cmd = sys.argv[1]
pid, master_fd = pty.fork()
if pid == 0:
    os.execvp("/bin/bash", ["/bin/bash", "-c", cmd])

try:
    winsize = struct.pack("HHHH", 34, 120, 0, 0)
    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
except Exception:
    pass

stdin_fd = sys.stdin.fileno()
stdout_fd = sys.stdout.fileno()
stdin_open = True

def forward_sig(signum, _frame):
    try:
        os.killpg(pid, signum)
    except Exception:
        try:
            os.kill(pid, signum)
        except Exception:
            pass

signal.signal(signal.SIGTERM, forward_sig)
signal.signal(signal.SIGINT, forward_sig)

while True:
    rlist = [master_fd] + ([stdin_fd] if stdin_open else [])
    try:
        readable, _, _ = select.select(rlist, [], [], 0.25)
    except InterruptedError:
        continue

    if master_fd in readable:
        try:
            data = os.read(master_fd, 4096)
        except OSError:
            break
        if not data:
            break
        os.write(stdout_fd, data)

    if stdin_open and stdin_fd in readable:
        try:
            inp = os.read(stdin_fd, 4096)
        except OSError:
            stdin_open = False
            continue
        if not inp:
            stdin_open = False
        else:
            try:
                os.write(master_fd, inp)
            except OSError:
                break

try:
    os.close(master_fd)
except Exception:
    pass

_, status = os.waitpid(pid, 0)
if os.WIFEXITED(status):
    sys.exit(os.WEXITSTATUS(status))
if os.WIFSIGNALED(status):
    sys.exit(128 + os.WTERMSIG(status))
sys.exit(1)
