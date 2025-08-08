"""
This file is supposed to import the pyjdb module and setup a TCP listening server
"""
import sys
import json
import socket
from contextlib import contextmanager
from typing import Optional

import pyjdb


class JDBServer:
    """A class to proxy commands between Dyva and PyJDB
    """
    def __init__(self, conn):
        self.conn = conn
        self.finished = False
        self.py_jdb: Optional[pyjdb.JDBProcess] = None

    def get_next_request(self):
        """
        Get the next request from the client.
        """
        while not self.finished:
            print("[DEBUG] Waiting for data...")
            total_data = b""
            while True:
                data = self.conn.recv(1024, socket.MSG_PEEK)
                eol = data.find(b'\n')
                if eol >= 0:
                    size = eol + 1
                else:
                    size = len(data)
                data = self.conn.recv(size)
                if not data:
                    break
                print(f"[DEBUG] Received data: {data.decode('utf-8')}")
                total_data += data
                if len(data) < 1024:
                    break
            print(f"[DEBUG] Received request: {total_data.decode('utf-8')}")
            yield total_data.decode('utf-8')

    def send_response(self, response):
        """
        Send a response back to the client.
        """
        self.conn.sendall(response.encode('utf-8'))
        self.finished = response == "exit"

    def service_request(self, request) -> str:
        """
        Service the incoming request.
        """
        try:
            obj = json.loads(request)
        except json.JSONDecodeError:
            print(f"Invalid request: {request}")
            return json.dumps({"status": "error", "data": "Invalid request format"})

        cmd = obj.get("cmd", "")
        if cmd in ["exit", "quit"]:
            if self.py_jdb is not None:
                self.py_jdb.close()
            self.finished = True
            return json.dumps({"status": "success", "data": "Server shutting down"})
        elif cmd == "load":
            # Example
            # {'classname': 'Harness', 'classpath': '/out/mock-java.jar'}
            harness_classname = obj.get('classname', "")
            classpath = obj.get('classpath', "")
            sourcepath = obj.get('sourcepath')
            args = obj.get('args', [])
            self.py_jdb = pyjdb.JDBProcess(harness_classname, classpath, source_path=sourcepath)
            self.py_jdb.start_jdb(args)
            return json.dumps({"status": "success", "data": ""})
        elif cmd == "run":
            # Example
            # {'args': ['/work/pov_input']}
            self.py_jdb.run()
            return json.dumps({"status": "success", "data": ""})
        elif cmd in ["finish", "cont"]:
            func = getattr(self.py_jdb, cmd, None)
            func()
            return json.dumps({"status": "success", "data": ""})
        elif cmd in ['step', 'next', 'up', 'down']:
            arg = obj.get('arg', 1)
            func = getattr(self.py_jdb, cmd, None)
            func(arg)
            return json.dumps({"status": "success", "data": ""})
        elif cmd in ["set_breakpoint", "remove_breakpoint"]:
            arg = obj.get("location", "")
            func = getattr(self.py_jdb, cmd, None)
            func(arg)
            return json.dumps({"status": "success", "data": ""})
        elif cmd == "backtrace":
            backtrace = self.py_jdb.backtrace()
            return json.dumps({"status": "success", "data": backtrace})
        elif cmd == "local_variables":
            local_vars = self.py_jdb.local_variables()
            return json.dumps({"status": "success", "data": local_vars})
        elif cmd == "raw":
            arg = obj.get('arg', "")
            self.py_jdb.raw(arg)
            return json.dumps({"status": "success", "data": ""})
        else:
            raise NotImplementedError(f"Command '{cmd}' not implemented")

    def main_loop(self):
        print("Starting JDB server...")
        for request in self.get_next_request():
            resp = self.service_request(request)
            self.send_response(resp)


@contextmanager
def create_tcp_server(port: int):
    """
    Create a TCP server that listens on the specified port.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print(f"Listening on port {port}...")
    
    try:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        yield client_socket
    finally:
        client_socket.close()
        server_socket.close()
        print("Server closed.")


def main(port: int):
    """
    Main function to start the JDB server.
    """
    with create_tcp_server(port) as conn:
        jdb_server = JDBServer(conn)
        jdb_server.main_loop()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python start_jdb_server.py <port>")
        sys.exit(1)
    
    port = int(sys.argv[1])
    print(f"Starting JDB server on port {port}")

    main(port)
