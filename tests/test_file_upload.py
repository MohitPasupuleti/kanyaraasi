"""
Test Script for File Upload Functionality

This script tests the local-first security architecture for file uploads.
It verifies that secrets are detected locally before any external API calls.

Usage:
    python test_file_upload.py

Requirements:
    - LeakLockAI server must be running on http://localhost:8000
    - Test files must exist in ../test_files/ directory
"""

import requests
import os
import sys
from pathlib import Path
import json


# Configuration
BASE_URL = "http://localhost:8000"
TEST_FILES_DIR = Path(__file__).parent.parent / "test_files"


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_result(test_name, passed, message):
    """Print test result with color."""
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"\n{status} - {test_name}")
    print(f"   {message}")


def check_server_health():
    """Check if the LeakLockAI server is running."""
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Server is healthy")
            print(f"   File upload enabled: {data.get('file_upload_enabled', False)}")
            print(f"   Gemini configured: {data.get('gemini_configured', False)}")
            return True
        else:
            print(f"❌ Server returned status code: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to server at {BASE_URL}")
        print(f"   Make sure the server is running: python main.py")
        return False
    except Exception as e:
        print(f"❌ Error checking server health: {str(e)}")
        return False


def test_safe_document():
    """
    Test 1: Safe document with no secrets or PII
    Expected: ALLOW or SANITIZE with low risk score
    """
    test_name = "Test 1: Safe Document"
    file_path = TEST_FILES_DIR / "safe_document.txt"

    if not file_path.exists():
        print_result(test_name, False, f"Test file not found: {file_path}")
        return False

    try:
        with open(file_path, 'rb') as f:
            files = {'file': ('safe_document.txt', f, 'text/plain')}
            data = {'use_case': 'general'}
            response = requests.post(f"{BASE_URL}/analyze-file", files=files, data=data)

        if response.status_code != 200:
            print_result(test_name, False, f"HTTP {response.status_code}: {response.text}")
            return False

        result = response.json()

        # Validate response
        decision = result.get('decision')
        risk_score = result.get('risk_score', 0)

        if decision in ['ALLOW', 'SANITIZE'] and risk_score < 30:
            print_result(test_name, True, f"Decision: {decision}, Risk Score: {risk_score}/100")
            print(f"   Explanation: {result.get('explanation', 'N/A')}")
            return True
        else:
            print_result(test_name, False, f"Unexpected decision: {decision}, Risk: {risk_score}")
            return False

    except Exception as e:
        print_result(test_name, False, f"Error: {str(e)}")
        return False


def test_terminal_with_secrets():
    """
    Test 2: Terminal output with AWS credentials
    Expected: BLOCK with high risk score, Gemini NEVER called
    """
    test_name = "Test 2: Terminal with Secrets (Critical Security Test)"
    file_path = TEST_FILES_DIR / "terminal_with_secrets.txt"

    if not file_path.exists():
        print_result(test_name, False, f"Test file not found: {file_path}")
        return False

    try:
        with open(file_path, 'rb') as f:
            files = {'file': ('terminal_with_secrets.txt', f, 'text/plain')}
            data = {'use_case': 'debugging'}
            response = requests.post(f"{BASE_URL}/analyze-file", files=files, data=data)

        if response.status_code != 200:
            print_result(test_name, False, f"HTTP {response.status_code}: {response.text}")
            return False

        result = response.json()

        # Critical validations
        decision = result.get('decision')
        risk_score = result.get('risk_score', 0)
        gemini_called = result.get('gemini_called', True)  # Default to True to catch if missing
        processing_method = result.get('processing_method', 'unknown')

        # Test MUST pass all these conditions
        conditions = [
            (decision == 'BLOCK', f"Decision should be BLOCK, got: {decision}"),
            (risk_score >= 80, f"Risk score should be high (>=80), got: {risk_score}"),
            (gemini_called == False, f"❌ CRITICAL: Gemini should NOT be called when secrets detected! gemini_called={gemini_called}"),
            (processing_method == 'local_only', f"Processing method should be 'local_only', got: {processing_method}")
        ]

        all_passed = all(condition[0] for condition in conditions)

        if all_passed:
            print_result(test_name, True, "All security checks passed!")
            print(f"   ✅ Decision: {decision}")
            print(f"   ✅ Risk Score: {risk_score}/100")
            print(f"   ✅ Gemini Called: {gemini_called} (correct - secrets never sent)")
            print(f"   ✅ Processing Method: {processing_method}")
            print(f"   ✅ Zero-Leak Guarantee: VERIFIED")
            return True
        else:
            print_result(test_name, False, "Security validation failed!")
            for condition, message in conditions:
                status = "✅" if condition else "❌"
                print(f"   {status} {message}")
            return False

    except Exception as e:
        print_result(test_name, False, f"Error: {str(e)}")
        return False


def test_document_with_pii():
    """
    Test 3: Document with PII (emails, phone numbers)
    Expected: SANITIZE after local PII detection
    """
    test_name = "Test 3: Document with PII"
    file_path = TEST_FILES_DIR / "document_with_pii.txt"

    if not file_path.exists():
        print_result(test_name, False, f"Test file not found: {file_path}")
        return False

    try:
        with open(file_path, 'rb') as f:
            files = {'file': ('document_with_pii.txt', f, 'text/plain')}
            data = {'use_case': 'document_analysis'}
            response = requests.post(f"{BASE_URL}/analyze-file", files=files, data=data)

        if response.status_code != 200:
            print_result(test_name, False, f"HTTP {response.status_code}: {response.text}")
            return False

        result = response.json()

        # Validate response
        decision = result.get('decision')
        risk_score = result.get('risk_score', 0)
        processing_method = result.get('processing_method', 'unknown')

        # PII should be detected and sanitized
        if decision == 'SANITIZE' and 20 <= risk_score <= 70:
            print_result(test_name, True, "PII detected and sanitized correctly")
            print(f"   Decision: {decision}")
            print(f"   Risk Score: {risk_score}/100")
            print(f"   Processing: {processing_method}")
            print(f"   Explanation: {result.get('explanation', 'N/A')}")
            return True
        else:
            print_result(test_name, False, f"Unexpected result - Decision: {decision}, Risk: {risk_score}")
            return False

    except Exception as e:
        print_result(test_name, False, f"Error: {str(e)}")
        return False


def test_unsupported_file_type():
    """
    Test 4: Unsupported file type
    Expected: BLOCK with appropriate error message
    """
    test_name = "Test 4: Unsupported File Type"

    try:
        # Create a fake file with unsupported extension
        files = {'file': ('test.xyz', b'This is a test', 'application/octet-stream')}
        data = {'use_case': 'general'}
        response = requests.post(f"{BASE_URL}/analyze-file", files=files, data=data)

        if response.status_code != 200:
            print_result(test_name, False, f"HTTP {response.status_code}")
            return False

        result = response.json()
        decision = result.get('decision')

        if decision == 'BLOCK' and 'Unsupported' in result.get('explanation', ''):
            print_result(test_name, True, "Unsupported file type handled correctly")
            print(f"   Explanation: {result.get('explanation', 'N/A')}")
            return True
        else:
            print_result(test_name, False, f"Unexpected response: {result}")
            return False

    except Exception as e:
        print_result(test_name, False, f"Error: {str(e)}")
        return False


def main():
    """Run all tests."""
    print_section("LeakLockAI File Upload Test Suite")
    print("Testing local-first security architecture")
    print(f"Target: {BASE_URL}")
    print(f"Test files: {TEST_FILES_DIR}")

    # Check server health first
    print_section("Server Health Check")
    if not check_server_health():
        print("\n❌ Server is not available. Please start the server first:")
        print("   cd src && python main.py")
        sys.exit(1)

    # Run all tests
    print_section("Running Test Cases")

    results = []
    results.append(("Safe Document", test_safe_document()))
    results.append(("Terminal with Secrets", test_terminal_with_secrets()))
    results.append(("Document with PII", test_document_with_pii()))
    results.append(("Unsupported File Type", test_unsupported_file_type()))

    # Summary
    print_section("Test Summary")
    passed = sum(1 for _, result in results if result)
    total = len(results)

    print(f"\nResults: {passed}/{total} tests passed")
    print()

    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {name}")

    print()

    if passed == total:
        print("🎉 All tests passed! File upload security is working correctly.")
        print("✅ Zero-leak architecture verified")
        return 0
    else:
        print("⚠️  Some tests failed. Please review the output above.")
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {str(e)}")
        sys.exit(1)
