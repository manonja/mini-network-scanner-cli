#!/bin/bash
program="$1"
shift  # Remove first argument (program path)

# Start program with sudo and stop it immediately
sudo "$program" "$@" & 
pid=$!
echo $pid > /tmp/debug_pid

# Send SIGSTOP to pause the process
kill -STOP $pid

# Verify process is running
if ps -p $pid > /dev/null; then
    echo "Process started and paused with PID: $pid"
else
    echo "Process failed to start"
    exit 1
fi

wait $pid

