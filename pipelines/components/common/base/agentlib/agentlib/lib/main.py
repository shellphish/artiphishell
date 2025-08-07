#!/usr/bin/env python3
import os
import json
import argparse

#from query_guy import QueryGuy
from web_guy import WebGuy

import argparse

def run_display_server(args):
    from web_console import app
    app.run(host=args.host, port=args.port)

def run_web_guy(args):
    from web_guy import WebGuy
    wg = WebGuy.test(args)

def main():
    argp = argparse.ArgumentParser(description='')
    subp = argp.add_subparsers(help='Choose a subcommand')

    displayp = subp.add_parser('display', help='Run the display server')
    displayp.add_argument('--host', default='0.0.0.0', help='The host to bind to')
    displayp.add_argument('--port', default=5000, help='The port to bind to')
    displayp.set_defaults(func=run_display_server)

    webguyp = subp.add_parser('webguy', help='Run the web guy')
    webguyp.set_defaults(func=run_web_guy)

    args = argp.parse_args()
    args.func(args)

    #qg = QueryGuy.test()
    #wg = WebGuy.test()
    #pass

import langchain
import logging

if __name__ == '__main__':
    #langchain.verbose = True
    #langchain.debug = True
    #logging.basicConfig(level=logging.DEBUG)

    main()