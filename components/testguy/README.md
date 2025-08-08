# TestGuy Component

This is the TestGuy Component that first identies unit tests in a repository based on pre-defined rules for the given oss-fuzz target. Second, it runs these unit tests and records the successful tests for the target. Then it returns the following three pieces of informations:

1. script to run the unit tests
2. script to parse the results of the unit tests
3. initial results of the tests for the given target - which will be compared later with the post-patch target using testguy lib
