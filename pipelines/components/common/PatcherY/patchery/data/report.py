class Report:
    def __init__(self, raw_data):
        self.raw_data = raw_data

    def redner(self) -> str:
        raise NotImplementedError
