import os
from shellphish_crs_utils import LIBS_DIR

from nautilus_python import PyGenerator

BASE_DIR = "/shellphish/grammar-composer"
REFERENCE_GRAMMARS_DIR = LIBS_DIR / "nautilus/grammars/reference"

REFERENCE_GRAMMARS_FILEPATHS = {
    fname.split(".")[0]: f"{REFERENCE_GRAMMARS_DIR}/{fname}" 
    for fname in os.listdir(REFERENCE_GRAMMARS_DIR) 
    if fname.endswith(".py")
}
