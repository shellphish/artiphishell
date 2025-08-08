import argparse
import sys
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("events_dir")
    args = parser.parse_args()

    args.events_dir = Path(args.events_dir)
    if not args.events_dir.exists():
        print(f"Events directory {args.events_dir} does not exist")
        sys.exit(1)
    if not args.events_dir.is_dir():
        print(f"Events directory {args.events_dir} is not a directory")
        sys.exit(1)

    www_dir = Path(__file__).resolve().parent.parent / "www"
    events_dir_symlink = www_dir / "events_dir"
    events_dir_symlink.unlink(missing_ok=True)
    events_dir_symlink.symlink_to(args.events_dir, target_is_directory=True)

    class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=www_dir, **kwargs)

    httpd = HTTPServer(("", 8000), CustomHTTPRequestHandler)
    httpd.serve_forever()
