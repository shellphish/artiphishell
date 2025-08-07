"""This module houses classes and instances related to host tracking.

Pydatatask needs to be able to know how to make resources accessible regardless of where they are. To this end, there
can be e.g. dicts of urls keyed on Hosts, indicating that a given target resource needs to be accessed through a
different url depending on which host is accessing it.
"""

from typing import Dict, Optional
from dataclasses import dataclass
from enum import Enum, auto
import getpass
import hashlib
import os
import random
import string


class HostOS(Enum):
    """The operating system provided by a host."""

    Linux = auto()


@dataclass(frozen=True)
class Host:
    """A descriptor of a host."""

    name: str
    os: HostOS

    def mktemp(self, identifier: str) -> str:
        """Generate a temporary filepath for the host system."""
        if self.os == HostOS.Linux:
            return (
                f"/tmp/pydatatask-{getpass.getuser()}-"
                f'{identifier}-{"".join(random.choice(string.ascii_lowercase) for _ in range(8))}'
            )
        else:
            raise TypeError(self.os)

    def mk_http_get(
        self, filename: str, url: str, headers: Dict[str, str], verbose: bool = False, handle_err: str = ""
    ) -> str:
        """Generate a shell script to perform an http download for the host system."""
        if self.os == HostOS.Linux:
            headers_str = " ".join(f'--header "{key}: {val}"' for key, val in headers.items())
            return f"""
            URL="{url}"
            FILENAME="$(mktemp)"
            ERR_FILENAME=$(mktemp)
            if [ -d "$FILENAME" ]; then echo "mk_http_get target $FILENAME is a directory" && false; fi

            for i in $(seq 1 3); do
                wget {'-v' if verbose else '-q'} -O- $URL {headers_str} >>$FILENAME 2>>$ERR_FILENAME || \\
                    curl -f {'-v' if verbose else ''} $URL {headers_str} >>$FILENAME 2>>$ERR_FILENAME || \\
                    (echo "download of $URL failed:" && cat $ERR_FILENAME $FILENAME
                    {handle_err}
                    false)
                CUR_DOWNLOAD_FAILED=$?
                if [ $CUR_DOWNLOAD_FAILED -eq 0 ]; then break; fi
                RETRY_DELAY=$((i * 10))
                echo "download failed, retrying in $RETRY_DELAY seconds"
                sleep $RETRY_DELAY
            done
            rm $ERR_FILENAME
            mv $FILENAME "{filename}" || cat $FILENAME >"{filename}" && rm -f $FILENAME
            """
        else:
            raise TypeError(self.os)

    def mk_http_post(
        self,
        filename: str,
        url: str,
        headers: Dict[str, str],
        output_filename: Optional[str] = None,
        verbose: bool = False,
        handle_err: str = "",
        required_for_success: bool = True,
    ) -> str:
        """Generate a shell script to perform an http upload for the host system."""
        if self.os == HostOS.Linux:
            output_redirect = ">>$OUTPUT_FILENAME" if output_filename else ">/dev/null"
            headers_str = " ".join(f'--header "{key}: {val}"' for key, val in headers.items())
            return f"""
            URL="{url}"
            FILENAME="{filename}"
             {'OUTPUT_FILENAME="$(mktemp)"' if output_filename else ''}
            ERR_FILENAME=$(mktemp)
            ANY_UPLOADS_FAILED=${{ANY_UPLOADS_FAILED:-0}}
            if ! [ -e "$FILENAME" ]; then
                echo "mk_http_post target $FILENAME does not exist"
                {'ANY_UPLOADS_FAILED=1' if required_for_success else ''}
            fi
            if [ -f "$FILENAME" ]; then 
                for i in $(seq 1 3); do
                    wget {'-v' if verbose else '-q'} -O- $URL {headers_str} --post-file $FILENAME 2>>$ERR_FILENAME {output_redirect} || \\
                        curl -f {'-v' if verbose else ''} $URL {headers_str} -T $FILENAME -X POST 2>>$ERR_FILENAME {output_redirect} || \\
                        (echo "upload of $URL failed:" && cat $ERR_FILENAME {'$OUTPUT_FILENAME ' if output_filename else ''}
                        {handle_err}
                        false)
                    CUR_UPLOAD_FAILED=$?
                    if [ $CUR_UPLOAD_FAILED -eq 0 ]; then break; fi
                    RETRY_DELAY=$((i * 10))
                    echo "upload failed, retrying in $RETRY_DELAY seconds"
                    sleep $RETRY_DELAY
                done
                if [ $CUR_UPLOAD_FAILED -ne 0 ]; then
                    ANY_UPLOADS_FAILED=1
                fi
            else
                echo "mk_http_post target $FILENAME is not a file"
                {'ANY_UPLOADS_FAILED=1' if required_for_success else ''}
            fi
            rm $ERR_FILENAME
            {f'mv $OUTPUT_FILENAME "{output_filename}" || cat $OUTPUT_FILENAME >"{output_filename}" && rm -f $OUTPUT_FILENAME' if output_filename else ''}
            """
        else:
            raise TypeError(self.os)

    def mk_unzip(self, output_filename: str, input_filename: str) -> str:
        """Generate a shell script to unpack an archive for the host system."""
        if self.os == HostOS.Linux:
            return f"""
            mkdir -p {output_filename}
            cd {output_filename}
            tar -xf {input_filename}
            cd -
            """
        else:
            raise TypeError(self.os)

    def mk_zip(self, output_filename: str, input_filename: str) -> str:
        """Generate a shell script to pack an archive for the host system."""
        if self.os == HostOS.Linux:
            return f"""
            cd {input_filename}
            tar -cf {output_filename} .
            cd -
            """
        else:
            raise TypeError(self.os)

    def mk_mkdir(self, filepath: str) -> str:
        """Generate a shell script to make a directory for the host system."""
        if self.os == HostOS.Linux:
            return f"mkdir -p {filepath}"
        else:
            raise TypeError(self.os)

    def mk_cache_get_static(self, dest_filepath: str, cache_key: str, miss, cache_dir) -> str:
        if self.os == HostOS.Linux:
            cp = "cp"
            cache_key_hash = hashlib.md5(cache_key.encode()).hexdigest()
            tick = "'"
            backslash = "\\"
            cache_key_sane = f'{cache_key.replace("/", "-").replace(" ", "-").replace(backslash, "-").replace(tick, "-")[:55]}-{cache_key_hash[:8]}'
            cache_key_dirname = f"{cache_dir}/{cache_key_hash[:2]}"
            cache_key_path = f"{cache_key_dirname}/{cache_key_sane}"
            return f"""
            while true; do
              if [ -f "{cache_key_path}" ]; then
                 {cp} "{cache_key_path}" "{dest_filepath}"
              else
                mkdir -p "{cache_key_dirname}"
                if mkdir "{cache_key_path}.lock"; then
                  {miss}
                  {cp} "{dest_filepath}" "{cache_key_path}"
                  rm -rf "{cache_key_path}.lock"
                else
                  while [ -d "{cache_key_path}.lock" ]; do
                    if [ "$(($(date +%s) - $(stat -c %W "{cache_key_path}.lock")))" -ge 300 ]; then
                      rm -rf "{cache_key_path}.lock"
                      continue
                    fi
                    sleep 5
                  done
                  {cp} "{cache_key_path}" "{dest_filepath}"
                fi
              fi
              break
            done
            """
        else:
            raise TypeError(self.os)


_uname = os.uname()
if _uname.sysname == "Linux":
    LOCAL_OS = HostOS.Linux
else:
    raise ValueError(f"Unsupported local system {_uname.sysname}")

LOCAL_HOST = Host("localhost", LOCAL_OS)
