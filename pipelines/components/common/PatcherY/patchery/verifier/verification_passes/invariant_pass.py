from .base_verification_pass import BaseVerificationPass


class TraceInvariantPass(BaseVerificationPass):
    def __init__(self, *args, must_validate=False, requires_executor=True, **kwargs):
        super().__init__(*args, must_validate=must_validate, requires_executor=requires_executor, **kwargs)

    def _verify(self):
        # TODO: implement me
        return False, "Not implemented"
