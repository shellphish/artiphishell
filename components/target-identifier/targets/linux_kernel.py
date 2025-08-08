import logging
import subprocess

LOG = logging.getLogger(__name__)

def is_linux_kernel(root, dirs, files):
    if not {'Kbuild', 'Kconfig', 'Makefile'}.issubset(files):
        return None
    if not {'net', 'fs', 'arch'}.issubset(dirs):
        return None

    try:
        version = subprocess.check_output(['make', 'kernelversion'], cwd=root).decode('utf-8').strip()
    except Exception as ex:
        LOG.error(f"Error while running make kernelversion in {root}: {ex}")
        version = None

    LOG.info(f"Found Linux kernel in {root} with version {version}")

    return {
        'version': version
    }
