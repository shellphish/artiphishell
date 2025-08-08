#Just a test script to run the server
socat tcp-l:12345,fork EXEC:"./clangd_19.1.2/bin/clangd --log=verbose --compile-commands-dir==absolute/path/to/compile_commands.json"
