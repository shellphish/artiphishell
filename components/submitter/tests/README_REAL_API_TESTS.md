# Real API Integration Tests for Submitter

This directory contains integration tests that run against the real Competition API server instead of using mocked API responses. These tests are useful for verifying that the Submitter component works correctly with the actual API implementation.

## Prerequisites

- Docker installed and running
- The `aixcc-afc-competition-api` Docker image available locally

## Running the Tests

To run the integration tests with the real API server, use the provided script:

```bash
./components/submitter/run_real_api_tests.sh
```

This script will:

1. Start a Docker container running the Competition API server if it's not already running
2. Get the container's IP address
3. Set the necessary environment variables for the tests
4. Run the integration tests
5. Optionally stop and remove the container when done

## Test Configuration

The tests use the following environment variables:

- `AIXCC_API_HOST`: The URL of the API server (default: `http://<container-ip>:80`)
- `AIXCC_API_USER`: The username for API authentication (default: `test-user`)
- `AIXCC_API_TOKEN`: The token for API authentication (default: `test-token`)

You can override these variables by setting them before running the script:

```bash
AIXCC_API_USER="custom-user" AIXCC_API_TOKEN="custom-token" ./components/submitter/run_real_api_tests.sh
```

## Test Cases

The integration tests cover the following functionality:

1. Vulnerability submission
2. Patch submission
3. SARIF assessment submission
4. Bundle submission

Each test creates the necessary test data, submits it to the API, and verifies that the submission was successful.

## Troubleshooting

If the tests fail, check the following:

1. Make sure the API container is running and accessible
2. Verify that the API credentials are correct
3. Check the API server logs for any errors:
   ```bash
   docker logs aixcc-afc-competition-api-test
   ```

## Adding New Tests

To add new integration tests, add new test functions to the `test_submitter_real_api.py` file. Make sure to:

1. Use the `submitter_real_api` fixture to get a Submitter instance configured with the real API
2. Create unique test data for each test run to avoid conflicts
3. Clean up any test data created during the test 