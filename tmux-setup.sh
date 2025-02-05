#!/bin/bash

# Create a new tmux session named 'debug'
tmux new-session -d -s debug

# Window 0: tcpdump
tmux send-keys -t debug:0 'tcpdump -i lo -nn "tcp[tcpflags] & tcp-syn != 0"' C-m

# Window 1: TCP server
tmux new-window -t debug:1
tmux send-keys -t debug:1 'cd /home/developer/app/tcp-server && ./tcp-dump 127.0.0.1 8080' C-m

# Window 2: Your Rust project (maja-scan)
tmux new-window -t debug:2
tmux send-keys -t debug:2 'cd /home/developer/app && ./target/debug/maja-scan --scan 127.0.0.1:8080 --src 127.0.0.1' C-m

# Attach to the tmux session
tmux attach-session -t debug