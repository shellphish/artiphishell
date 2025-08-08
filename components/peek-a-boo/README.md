# artiphishell-corpus.sh

This script is designed to run coverage analysis for OSS-Fuzz projects using either aflpp or jazzer. It allows you to select a project, a fuzzer, and a harness, and then use existing artifacts and a seed corpus for coverage analysis.

## Corpus Options

This script supports two main ways to provide a seed corpus for fuzzing:

1.  **OSS-Fuzz Corpus**: You can use the fuzzer sync directory provided by OSS-Fuzz, which might contain a pre-existing corpus.

2.  **Artiphishell Corpus (Our Backups)**:
    *   **Fuzzer sync**: We don't save it anymore for CI runs.
    *   **Benign seeds collected from fuzzing**: Utilize seeds that have been collected during previous fuzzing runs.
    *   **Custom corpus**: Specify an absolute path to your own custom corpus directory.
    *   **Automatically collect seeds from libpermanence**: Automatically downloads and extracts seeds for a given project and harness from the libpermanence service.

## Usage

To run the script, execute it from your terminal:

```bash
./run.sh
```

### Interactive Prompts:

During execution, the script will prompt you for the following information:

1.  **Fuzzer Name**: Choose between `aflpp` or `jazzer`.
2.  **Harness Selection**: Select one of the available harnesses for the chosen project.
3.  **Corpus Choice**: Choose where to get the seed corpus from:
    *   `1. Fuzzer sync directory`: You will be prompted to enter the path to the unpacked fuzzer sync directory.
    *   `2. Benign seeds collected from fuzzing`: Uses seeds collected during fuzzing.
    *   `3. Custom corpus`: You will be prompted to enter the absolute path to your custom corpus directory.
    *   `4. Automatically collect seeds from libpermanence`: Automatically downloads and extracts seeds from the libpermanence service.

## Functionality

*   **OSS-Fuzz Setup**: Clones the OSS-Fuzz repository if not already present.
*   **Artifact Preparation**: Prepares build artifacts based on the selected fuzzer (C for aflpp, Java for jazzer) and copies them to the OSS-Fuzz build directory.
*   **Corpus Preparation**: Collects and copies the seed corpus based on your selection (fuzzer sync, benign seeds, custom, or libpermanence).
*   **Coverage Analysis**: Runs coverage analysis using `infra/helper.py coverage` with the prepared artifacts and corpus. 