#!/usr/bin/env bash


while true; do
    socat UNIX-LISTEN:/src/gdb.socket,fork TCP-CONNECT:localhost:12345 &
    PID=$!
    gdbserver --multi :12345 ./real_harness /src/input
    kill -9 $PID
    rm /src/gdb.socket
done