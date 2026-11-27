#!/usr/bin/env python3
import fcntl, os, pty, re, select, signal, struct, sys, termios

if len(sys.argv) < 2:
    sys.exit(2)

cols = 120
rows = 34
if len(sys.argv) >= 4 and sys.argv[1].isdigit() and sys.argv[2].isdigit():
    cols = max(40, min(300, int(sys.argv[1])))
    rows = max(12, min(120, int(sys.argv[2])))
    cmd = sys.argv[3]
else:
    cmd = sys.argv[1]

pid, master_fd = pty.fork()
if pid == 0:
    os.execvp("/bin/bash", ["/bin/bash", "-c", cmd])

def set_winsize(r, c):
    try:
        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", r, c, 0, 0))
        os.killpg(pid, signal.SIGWINCH)
    except Exception:
        pass

set_winsize(rows, cols)

stdin_fd = sys.stdin.fileno()
stdout_fd = sys.stdout.fileno()
stdin_open = True
resize_re = re.compile(rb"\x1b\]9999;resize;(\d+);(\d+)\x07")

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
            def _handle_resize(m):
                c = max(40, min(300, int(m.group(1))))
                r = max(12, min(120, int(m.group(2))))
                set_winsize(r, c)
                return b""
            cleaned = resize_re.sub(_handle_resize, inp)
            if cleaned:
                try:
                    os.write(master_fd, cleaned)
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
