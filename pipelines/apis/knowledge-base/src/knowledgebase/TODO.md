# Improvements

Check referenced URLs to discover CVE and CWE information

1. securityreason.com has CWEs that aren't in the CVE description
    - ```json
    {
        "name": "836",
        "tags": [
            "third-party-advisory",
            "x_refsource_SREASON"
        ],
        "url": "http://securityreason.com/securityalert/836"
    },
    ```

2. For all non-CWE CVEs, check the references to find CWE sources or at least best-effort guesses