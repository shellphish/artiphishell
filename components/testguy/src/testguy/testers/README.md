# Tester General Structure

```python
class Tester4Lang:
    def __init__(self, project: OSSFuzzProject, project_path_docker: str, project_path_build_src: str):
        self.project = project
        self.project_path_docker = project_path_docker
        self.project_path_build_src = project_path_build_src

    def run() -> RunImageResult:
        # run commands here to run unit tests
```
