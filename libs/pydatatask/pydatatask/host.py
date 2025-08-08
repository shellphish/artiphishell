"""This module houses classes and instances related to host tracking.

Pydatatask needs to be able to know how to make resources accessible regardless of where they are. To this end, there
can be e.g. dicts of urls keyed on Hosts, indicating that a given target resource needs to be accessed through a
different url depending on which host is accessing it.
"""

from typing import Dict, Optional, Any, List
from dataclasses import dataclass, field
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
                date || true;
                wget {'-v' if verbose else '-q'} -O- $URL {headers_str} >>$FILENAME 2>>$ERR_FILENAME || \\
                    curl -L -f {'-v' if verbose else ''} $URL {headers_str} >>$FILENAME 2>>$ERR_FILENAME || \\
                    (echo "download of $URL failed:" && cat $ERR_FILENAME $FILENAME
                    {handle_err}
                    false)
                CUR_DOWNLOAD_FAILED=$?
                date || true;
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
        nginx_url: Optional[str] = None,
        nginx_file: Optional[str] = None,
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
                    date || true
                    touch /tmp/.pdt_upload_lock || true
                    (
                        [ -f /tmp/.nginx_upload ] && \
                        [ -n "{nginx_url or ''}" ] && \
                        [ -n "{nginx_file or ''}" ] && \
                        curl -f {'-v' if verbose else ''} "{nginx_url or ''}" -T "$FILENAME" && \
                        curl -f {'-v' if verbose else ''} "$URL?nginx={nginx_file or ''}" -X POST
                    ) || wget {'-v' if verbose else '-q'} -O- $URL {headers_str} --post-file $FILENAME 2>>$ERR_FILENAME {output_redirect} || \\
                        curl -f {'-v' if verbose else ''} $URL {headers_str} -T $FILENAME -X POST 2>>$ERR_FILENAME {output_redirect} || \\
                        (echo "upload of $URL failed:" && cat $ERR_FILENAME {'$OUTPUT_FILENAME ' if output_filename else ''}
                        {handle_err}
                        false)
                    CUR_UPLOAD_FAILED=$?
                    date || true
                    if [ $CUR_UPLOAD_FAILED -eq 0 ]; then break; fi
                    RETRY_DELAY=$((i * 10))
                    echo "upload failed, retrying in $RETRY_DELAY seconds"
                    sleep $RETRY_DELAY
                done
                rm -f /tmp/.pdt_upload_lock || true
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
            date || true
            tar -xf {input_filename}
            date || true
            cd -
            """
        else:
            raise TypeError(self.os)

    def mk_zip(self, output_filename: str, input_filename: str) -> str:
        """Generate a shell script to pack an archive for the host system."""
        if self.os == HostOS.Linux:
            return f"""
            cd {input_filename}
            date || true
            ls -la . || true
            tar -cf {output_filename} .
            ls -la {output_filename} || true
            date || true
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

    def mk_cache_get_static(self, dest_filepath: str, cache_key: str, miss, cache_dir, use_cache_symlink: bool = False) -> str:
        if self.os == HostOS.Linux:
            cp = "cp"
            cache_key_hash = hashlib.md5(cache_key.encode()).hexdigest()
            tick = "'"
            backslash = "\\"
            if '{{' in cache_key:
                cache_key_sane = cache_key
                cache_key_dirname = f"{cache_dir}"
                cache_key_path = f"{cache_key_dirname}/{cache_key_sane}"
            else:
                cache_key_sane = f'{cache_key.replace("/", "-").replace(" ", "-").replace(backslash, "-").replace(tick, "-")[:55]}-{cache_key_hash[:8]}'
                cache_key_dirname = f"{cache_dir}/{cache_key_hash[:2]}"
                cache_key_path = f"{cache_key_dirname}/{cache_key_sane}"
            return f"""
            while true; do
              date || true
              if [ -e "{cache_key_path}" ] && [ ! -d "{cache_key_path}.lock" ]; then
                 sleep .5
                 rm -rf "{dest_filepath}" || true
                 {f'ln -s "{cache_key_path}" "{dest_filepath}" || ' if use_cache_symlink else ''} {cp} -r "{cache_key_path}" "{dest_filepath}"
              else
                mkdir -p "{cache_key_dirname}"
                if mkdir "{cache_key_path}.lock" && touch "{cache_key_path}.lock/timestamp"; then
                  rm -rf "{dest_filepath}" || true
                  {miss}
                  tmp_suffix=$(date +%s%N | tail -c 10)
                  rm -rf "{cache_key_path}.tmp.$tmp_suffix" || true
                  if {'true' if use_cache_symlink else 'false'}; then
                    mv "{dest_filepath}" "{cache_key_path}.tmp.$tmp_suffix"
                  else
                    {cp} -r "{dest_filepath}" "{cache_key_path}.tmp.$tmp_suffix"
                  fi
                  rm -rf "{cache_key_path}" || true
                  mv "{cache_key_path}.tmp.$tmp_suffix" "{cache_key_path}"
                  if {'true' if use_cache_symlink else 'false'}; then
                    ln -s "{cache_key_path}" {dest_filepath} || cp -r "{cache_key_path}" {dest_filepath}
                  fi
                  sleep 1
                  rm -rf "{cache_key_path}.lock" || true
                else
                  while [ -d "{cache_key_path}.lock" ]; do
                    echo "Waiting for lock to be released..." || true
                    sleep 5
                    if [ -f "{cache_key_path}.lock/timestamp" ] && \
                        stat_time=$(stat -c %W "{cache_key_path}.lock/timestamp" 2>/dev/null) && \
                        [ -n "$stat_time" ] && \
                        [ "$stat_time" -ne 0 ] && \
                        [ "$(($(date +%s) - $stat_time))" -ge 600 ] 2>/dev/null; then
                      rm -rf "{cache_key_path}.lock" || true
                      break
                    fi
                  done
                  sleep 5
                  continue
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

@dataclass
class HostNode:
    name: str

    def __init__(self, name: str):
        self.name = name

    def __str__(self):
        return f"{self.name}"

    def __repr__(self):
        return str(self)

class KubeHostNode(HostNode):
    labels: Dict[str, str]
    all_labels: Dict[str, str]
    taints: Dict[str, str]

    allocatable: Dict[str, str] = field(default_factory=dict)
    capacity: Dict[str, str] = field(default_factory=dict)

    def __init__(self, data: Any):
        # Extract all the data from the k8s api response
        md = data.metadata
        super().__init__(md.name)

        self.all_labels = md.labels
        self.labels = {k: v for k, v in self.all_labels.items() if k.startswith("support.shellphish.net/")}
        self.taints = {}

        spec = data.spec
        taints = spec.taints or []
        for taint in taints:
            if taint.effect == "PreferNoSchedule":
                # We don't care about preferNoSchedule taints as they are optional
                continue

            if taint.key.startswith("support.shellphish.net/"):
                self.taints[taint.key] = taint.value

        status = data.status
        self.allocatable = status.allocatable
        self.capacity = status.capacity


