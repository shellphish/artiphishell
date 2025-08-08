

import pexpect as _pexpect


class EOF(_pexpect.EOF):
    pass


class TIMEOUT(_pexpect.EOF):
    pass


class JdbHostExitedException(EOF):
    pass


class JdbHostErrorException(EOF):
    pass


class JdbException(TIMEOUT):
    pass
