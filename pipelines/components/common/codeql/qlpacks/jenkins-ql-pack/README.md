# Jenkins CodeQL

This repository contains Jenkins-specific CodeQL queries.

## Usage

1. Install the [CodeQL CLI](https://github.com/github/codeql-cli-binaries/releases).
2. Run `codeql pack install test/` to install the dependencies.

### Run tests

    codeql pack install test/
    codeql test run test/

The file `run-tests.sh` in this repository is a self-contained script that installs CodeQL, pack dependencies, and then runs the tests.
Since it downloads and extracts CodeQL CLI binaries, its use is not recommended for local development.

### Run queries against database

First, [generate or download a CodeQL database](https://codeql.github.com/docs/codeql-cli/creating-codeql-databases/) for the code base you want to run the queries against.

Then, run:

    codeql database codeql database analyze --format=sarifv2.1.0 --output=result.sarif <path to database> src/

This will generate the `result.sarif` file containing the query results.

## Development

### Update CodeQL

To update to a newer CodeQL release:

1. Determine which release to update to. See [the list of CodeQL releases](https://github.com/github/codeql-cli-binaries/releases) and [the corresponding releases of `java-all`](https://github.com/github/codeql/blob/main/java/ql/src/CHANGELOG.md).
2. Edit all `qlpack.yml` files and increase the version of `codeql/java-all` to the corresponding version in .
3. Run `codeql pack upgrade <dir>` on each of the directories containing a `qlpack.yml` file.
4. Edit `run-tests.sh` to download the correct CodeQL release and run it to confirm everything works as expected.

NOTE: https://github.com/jenkins-infra/jenkins-security-scan needs a corresponding change.
