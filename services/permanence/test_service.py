#!/usr/bin/env python3
"""
Testing script for the Permanence Service.
This script sends test requests to all endpoints to verify functionality.
"""

import os
import sys
import json
import base64
import httpx
import time
from typing import Dict, Any, List, Optional

# Constants
SERVICE_URL = os.environ.get("PERMANENCE_SERVICE_URL", "http://localhost:31337")
API_SECRET = os.environ.get("PERMANENCE_API_SECRET", "!!artiphishell!!")

# Test project and harness
PROJECT_NAME = "test_project"
HARNESS_NAME = "test_harness"

class PermanenceServiceTester:
    """
    Class to test the Permanence Service.
    """
    
    def __init__(self, base_url: str, api_secret: str):
        self.base_url = base_url
        self.api_secret = api_secret
        self.client = httpx.Client(base_url=base_url)
        self.client.headers.update({
            "SHELLPHISH_SECRET": api_secret,
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
    
    def check_service_status(self) -> bool:
        """
        Check if the service is running.
        """
        try:
            response = self.client.get("/status")
            if response.status_code == 200:
                print(f"✅ Service is running: {json.dumps(response.json(), indent=2)}")
                return True
            else:
                print(f"❌ Service returned status code {response.status_code}: {response.text}")
                return False
        except Exception as e:
            print(f"❌ Could not connect to service: {str(e)}")
            return False
    
    def test_indexed_functions(self) -> bool:
        """
        Test uploading indexed functions.
        """
        print("\n🔍 Testing indexed_functions endpoint...")
        
        # Create sample function data
        functions = {
            "module:file.c:function1": {
                "name": "function1",
                "file": "file.c",
                "module": "module",
                "start_line": 10,
                "end_line": 20,
                "is_exported": True,
                "signature": "int function1(char *input, size_t size)"
            },
            "module:file.c:function2": {
                "name": "function2",
                "file": "file.c",
                "module": "module",
                "start_line": 30,
                "end_line": 40,
                "is_exported": False,
                "signature": "void function2(void)"
            }
        }
        
        # Send the request
        try:
            response = self.client.post(
                f"/indexed_functions/{PROJECT_NAME}",
                json={
                    "functions": functions,
                    "extra": {
                        "test": True,
                        "timestamp": time.time()
                    }
                }
            )
            
            if response.status_code == 200:
                print(f"✅ Successfully uploaded indexed functions: {response.json()}")
                return True
            else:
                print(f"❌ Failed to upload indexed functions: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Exception when uploading indexed functions: {str(e)}")
            return False
    
    def test_grammar_reached_functions(self) -> bool:
        """
        Test uploading grammar reached functions.
        """
        print("\n🔍 Testing grammar_reached_functions endpoint...")
        
        # Create sample grammar data
        grammar_type = "json"
        grammar = """
        {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "value": {"type": "integer"}
            }
        }
        """
        
        hit_functions = [
            "module:file.c:function1",
            "module:file.c:function2"
        ]
        
        # Send the request
        try:
            response = self.client.post(
                f"/grammar_reached_functions/{PROJECT_NAME}/{HARNESS_NAME}",
                json={
                    "grammar_type": grammar_type,
                    "grammar": grammar,
                    "hit_functions": hit_functions,
                    "extra": {
                        "test": True,
                        "timestamp": time.time()
                    }
                }
            )
            
            if response.status_code == 200:
                print(f"✅ Successfully uploaded grammar reached functions: {response.json()}")
                return True
            else:
                print(f"❌ Failed to upload grammar reached functions: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Exception when uploading grammar reached functions: {str(e)}")
            return False
    
    def test_seed_reached_functions(self) -> bool:
        """
        Test uploading seed reached functions.
        """
        print("\n🔍 Testing seed_reached_functions endpoint...")
        
        # Create sample seed data
        seed = b'{"name":"test","value":42}'
        hit_functions = [
            "module:file.c:function1",
            "module:file.c:function2"
        ]
        
        # Send the request
        try:
            response = self.client.post(
                f"/seed_reached_functions/{PROJECT_NAME}/{HARNESS_NAME}",
                json={
                    "seed": base64.b64encode(seed).decode("utf-8"),
                    "hit_functions": hit_functions,
                    "extra": {
                        "test": True,
                        "timestamp": time.time()
                    }
                }
            )
            
            if response.status_code == 200:
                print(f"✅ Successfully uploaded seed reached functions: {response.json()}")
                return True
            else:
                print(f"❌ Failed to upload seed reached functions: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Exception when uploading seed reached functions: {str(e)}")
            return False
    
    def test_deduplicated_pov_report(self) -> bool:
        """
        Test uploading a deduplicated POV report.
        """
        print("\n🔍 Testing deduplicated_pov_report endpoint...")
        
        # Create sample report data
        dedup_report = {
            "crash_type": "buffer-overflow",
            "crash_address": "0x12345678",
            "crash_state": "function1\nfunction2\nfunction3",
            "crash_trace": [
                {"function": "function1", "file": "file.c", "line": 15},
                {"function": "function2", "file": "file.c", "line": 35},
                {"function": "function3", "file": "other_file.c", "line": 25}
            ],
            "reproduced": True,
            "sanitizer": "ASAN"
        }
        
        crashing_seed = b'{"name":"crash","value":-999999}'
        
        # Send the request
        try:
            response = self.client.post(
                f"/deduplicated_pov_report/{PROJECT_NAME}/{HARNESS_NAME}",
                json={
                    "dedup_sanitizer_report": dedup_report,
                    "crashing_seed": base64.b64encode(crashing_seed).decode("utf-8"),
                    "extra": {
                        "test": True,
                        "timestamp": time.time()
                    }
                }
            )
            
            if response.status_code == 200:
                print(f"✅ Successfully uploaded deduplicated POV report: {response.json()}")
                return True
            else:
                print(f"❌ Failed to upload deduplicated POV report: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Exception when uploading deduplicated POV report: {str(e)}")
            return False
    
    def test_poi_report(self) -> bool:
        """
        Test uploading a POI report.
        """
        print("\n🔍 Testing poi_report endpoint...")
        
        # Create sample report data
        poi_report = {
            "pois": [
                {
                    "type": "integer-overflow",
                    "source_location": {
                        "function_index_key": "module:file.c:function1",
                        "file": "file.c",
                        "line": 15,
                        "column": 10
                    },
                    "severity": "high",
                    "description": "Potential integer overflow in function1"
                },
                {
                    "type": "null-pointer-dereference",
                    "source_location": {
                        "function_index_key": "module:file.c:function2",
                        "file": "file.c",
                        "line": 35,
                        "column": 5
                    },
                    "severity": "medium",
                    "description": "Potential null pointer dereference in function2"
                }
            ],
            "analysis_metadata": {
                "timestamp": time.time(),
                "tool": "static-analyzer-1.0",
                "confidence": "high"
            }
        }
        
        # Send the request
        try:
            response = self.client.post(
                f"/poi_report/{PROJECT_NAME}/{HARNESS_NAME}",
                json={
                    "poi_report": poi_report,
                    "extra": {
                        "test": True,
                        "timestamp": time.time()
                    }
                }
            )
            
            if response.status_code == 200:
                print(f"✅ Successfully uploaded POI report: {response.json()}")
                return True
            else:
                print(f"❌ Failed to upload POI report: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Exception when uploading POI report: {str(e)}")
            return False
    
    def test_successful_patch(self) -> bool:
        """
        Test uploading a successful patch.
        """
        print("\n🔍 Testing successful_patch endpoint...")
        
        # Create sample data
        poi_report = {
            "pois": [
                {
                    "type": "integer-overflow",
                    "source_location": {
                        "function_index_key": "module:file.c:function1",
                        "file": "file.c",
                        "line": 15,
                        "column": 10
                    },
                    "severity": "high",
                    "description": "Potential integer overflow in function1"
                }
            ],
            "analysis_metadata": {
                "timestamp": time.time(),
                "tool": "static-analyzer-1.0",
                "confidence": "high"
            }
        }
        
        patch = """
        --- a/file.c
        +++ b/file.c
        @@ -15,7 +15,7 @@ int function1(char *input, size_t size) {
            int value = atoi(input);
            
            // Check for overflow before multiplying
        -   int result = value * 1000;
        +   int result = value > INT_MAX / 1000 ? INT_MAX : value * 1000;
            
            return result;
        }
        """
        
        functions_attempted = ["module:file.c:function1"]
        
        # Send the request
        try:
            response = self.client.post(
                f"/successful_patch/{PROJECT_NAME}/{HARNESS_NAME}",
                json={
                    "poi_report": poi_report,
                    "patch": patch,
                    "functions_attempted_to_patch": functions_attempted,
                    "extra": {
                        "test": True,
                        "timestamp": time.time()
                    }
                }
            )
            
            if response.status_code == 200:
                print(f"✅ Successfully uploaded successful patch: {response.json()}")
                return True
            else:
                print(f"❌ Failed to upload successful patch: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Exception when uploading successful patch: {str(e)}")
            return False
    
    def test_unsuccessful_patch_attempt(self) -> bool:
        """
        Test uploading an unsuccessful patch attempt.
        """
        print("\n🔍 Testing unsuccessful_patch_attempt endpoint...")
        
        # Create sample data
        poi_report = {
            "pois": [
                {
                    "type": "integer-overflow",
                    "source_location": {
                        "function_index_key": "module:file.c:function1",
                        "file": "file.c",
                        "line": 15,
                        "column": 10
                    },
                    "severity": "high",
                    "description": "Potential integer overflow in function1"
                }
            ],
            "analysis_metadata": {
                "timestamp": time.time(),
                "tool": "static-analyzer-1.0",
                "confidence": "high"
            }
        }
        
        functions_attempted = ["module:file.c:function1"]
        
        reasoning = """
        Attempted to fix the integer overflow in function1, but the solution
        introduced a regression where valid calculations that approach but
        don't exceed INT_MAX would incorrectly return INT_MAX. A more nuanced
        solution is needed.
        """
        
        # Send the request
        try:
            response = self.client.post(
                f"/unsuccessful_patch_attempt/{PROJECT_NAME}/{HARNESS_NAME}",
                json={
                    "poi_report": poi_report,
                    "reasoning": reasoning,
                    "functions_attempted_to_patch": functions_attempted
                }
            )
            
            if response.status_code == 200:
                print(f"✅ Successfully uploaded unsuccessful patch attempt: {response.json()}")
                return True
            else:
                print(f"❌ Failed to upload unsuccessful patch attempt: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Exception when uploading unsuccessful patch attempt: {str(e)}")
            return False
    
    def run_all_tests(self) -> Dict[str, bool]:
        """
        Run all tests and return the results.
        """
        results = {}
        
        # Check service status first
        if not self.check_service_status():
            print("❌ Service is not running, cannot run tests.")
            return {"service_status": False}
        
        results["service_status"] = True
        
        # Run all tests
        results["indexed_functions"] = self.test_indexed_functions()
        results["grammar_reached_functions"] = self.test_grammar_reached_functions()
        results["seed_reached_functions"] = self.test_seed_reached_functions()
        results["deduplicated_pov_report"] = self.test_deduplicated_pov_report()
        results["poi_report"] = self.test_poi_report()
        results["successful_patch"] = self.test_successful_patch()
        results["unsuccessful_patch_attempt"] = self.test_unsuccessful_patch_attempt()
        
        # Print summary
        print("\n📊 Test Summary:")
        for test, result in results.items():
            print(f"  {'✅' if result else '❌'} {test}")
        
        # Overall result
        all_passed = all(results.values())
        print(f"\n{'✅ All tests passed!' if all_passed else '❌ Some tests failed!'}")
        
        return results

def main():
    print(f"🔧 Testing Permanence Service at {SERVICE_URL}")
    
    tester = PermanenceServiceTester(SERVICE_URL, API_SECRET)
    results = tester.run_all_tests()
    
    # Exit with appropriate status code
    if all(results.values()):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()