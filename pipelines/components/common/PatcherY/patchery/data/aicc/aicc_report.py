from ..report import Report


class AICCReport(Report):
    def __init__(self, raw_data: str, harness_id, harness_name, sanitizer_string):
        super().__init__(raw_data)
        self.harness_id = harness_id
        self.harness_name = harness_name
        self.sanitizer_string = sanitizer_string
