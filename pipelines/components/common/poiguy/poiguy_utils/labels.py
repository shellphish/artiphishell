from enum import Enum


class DetectionStrategy(Enum):
    FUZZING = 'fuzzing'
    STATIC_ANALYSIS = 'static_analysis'

    def __str__(self):
        return self.value


class Scanner(Enum):
    JAZZER = 'jazzer'
    SYZKALLER = 'syzkaller'
    ASAN = 'asan'

    def __str__(self):
        return self.value


class FileName(Enum):
    KASAN_REPORT = 'repro.report'
    C_REPRODUCER = 'repro.cprog'
    SYZLANG_REPRODUCER = 'repro.prog'
    CLANG_INDEX = 'output.csv'
    SYZKALLER_POI = 'syzkaller-poi-report.yaml'
    JAZZER_POI = 'jazzer-poi-report.yaml'
    JAZZER_REPORT = 'crash.json'

    def __str__(self):
        return self.value
