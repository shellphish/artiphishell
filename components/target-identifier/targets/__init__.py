TARGET_IDENTIFIERS = {}
# def register_target_analyzer(target_identifier):
#     def _register_target_analyzer(target_analyzer):
#         TARGET_IDENTIFIERS[target_identifier] = target_analyzer
#     return _register_target_analyzer

from .linux_kernel import is_linux_kernel
from .jenkins import is_jenkins_plugin, is_jenkins_root
from .pcre2 import is_pcre2
from .libxml2 import is_libxml2
from .libpng import is_libpng
from .libwebp import is_libwebp
from .giflib import is_giflib_old, is_giflib_new
from .libzip import is_libzip

TARGET_IDENTIFIERS['linux_kernel'] = [is_linux_kernel]
TARGET_IDENTIFIERS['jenkins_core'] = [is_jenkins_root]
TARGET_IDENTIFIERS['jenkins_plugin'] = [is_jenkins_plugin]
TARGET_IDENTIFIERS['pcre2'] = [is_pcre2]
TARGET_IDENTIFIERS['libxml2'] = [is_libxml2]
TARGET_IDENTIFIERS['libpng'] = [is_libpng]
TARGET_IDENTIFIERS['libwebp'] = [is_libwebp]
TARGET_IDENTIFIERS['giflib'] = [is_giflib_old, is_giflib_new]
TARGET_IDENTIFIERS['libzip'] = [is_libzip]