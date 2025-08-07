class BaseTask:
    pass

class HarnessTask(BaseTask):
    def __init__(self, harness_code, trace_info_prompt, jazzer_sanitizer_description, use_model_name, harness_filepath):
        self.harness_code = harness_code
        self.trace_info_prompt = trace_info_prompt
        self.jazzer_sanitizer_description = jazzer_sanitizer_description
        self.use_model_name = use_model_name
        self.harness_filepath = harness_filepath
        
class PoisTask(BaseTask):
    def __init__(self, node_path, use_model_name):
        self.node_path = node_path
        self.use_model_name = use_model_name

class FilterPoisTask(BaseTask):
    def __init__(self, node_path, use_model_name, reason):
        self.node_path = node_path
        self.use_model_name = use_model_name
        self.reason = reason