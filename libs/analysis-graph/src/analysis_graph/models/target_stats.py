from neomodel import StringProperty, IntegerProperty, FloatProperty, ArrayProperty, DateTimeProperty
from analysis_graph.models import HarnessNode

class CoveragePerformanceStats(HarnessNode):
    last_100_inputs_average_tracing_time_millis = ArrayProperty(IntegerProperty())
    overall_average_tracing_time_millis = ArrayProperty(IntegerProperty())
    updates = ArrayProperty(DateTimeProperty())
