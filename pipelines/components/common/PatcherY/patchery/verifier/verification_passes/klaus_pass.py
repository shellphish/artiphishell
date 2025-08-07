from .base_verification_pass import BaseVerificationPass


class KlausVerificationPass(BaseVerificationPass):
    def __init__(self, *args, must_validate=False, kernel_pass=True, **kwargs):
        super().__init__(*args, must_validate=must_validate, kernel_pass=kernel_pass, **kwargs)

    def _verify(self):
        """
        TODO: implement https://www.usenix.org/system/files/usenixsecurity23-wu-yuhang.pdf
        """
        return False, "Not implemented"
