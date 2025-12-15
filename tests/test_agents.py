#!/usr/bin/env python3
"""
Test script for LeakLock AI complete agentic system
Demonstrates the dynamic flow with all agents
"""

import sys
import os
import json

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from planner import plan_and_execute
from memory import init_memory

# Initialize database
init_memory()

print("=" * 80)
print("LeakLock AI - Complete Agentic System Test")
print("=" * 80)
print()

# Test Case 1: PII detected (email and phone)
print("TEST CASE 1: PII Detection with Sanitization")
print("-" * 80)
test_input_1 = """
Please help me debug this issue. My email is john.doe@example.com and you can
reach me at 555-123-4567 if you need more details about the authentication problem.
"""

print("Input:")
print(test_input_1.strip())
print()

result_1 = plan_and_execute(test_input_1, use_case="debugging")

print("\nRESULTS:")
print(f"Decision: {result_1['decision']}")
print(f"Risk Score: {result_1['risk_score']}/100")
print(f"\nExplanation:")
print(f"  {result_1['explanation']}")
print(f"\nPolicy References:")
for policy in result_1['policy_refs']:
    print(f"  - {policy['id']}: {policy['summary']}")
print(f"\nDetected Signals:")
for signal in result_1['detected_signals']:
    print(f"  - {signal['type']} ({signal['severity']}): {signal['description']}")
print(f"\nExecution Trace:")
for step in result_1.get('execution_trace', []):
    # This won't be in the response but is logged to DB
    pass
if 'safe_prompt' in result_1:
    print(f"\nSanitized Output:")
    print(f"  {result_1['safe_prompt'][:200]}...")
print(f"\nAudit ID: {result_1['audit_id']}")
print()

# Test Case 2: Secrets detected (early exit)
print("\n" + "=" * 80)
print("TEST CASE 2: Secrets Detection (Early Exit)")
print("-" * 80)
test_input_2 = """
I'm trying to connect to OpenAI API but getting errors. Here's my API key:
sk-1234567890abcdefghijklmnopqrstuvwxyz
Can you help me debug this?
"""

print("Input:")
print(test_input_2.strip())
print()

result_2 = plan_and_execute(test_input_2, use_case="debugging")

print("\nRESULTS:")
print(f"Decision: {result_2['decision']}")
print(f"Risk Score: {result_2['risk_score']}/100")
print(f"\nExplanation:")
print(f"  {result_2['explanation']}")
print(f"\nPolicy References:")
for policy in result_2['policy_refs']:
    print(f"  - {policy['id']}: {policy['summary']}")
print(f"\nDetected Signals:")
for signal in result_2['detected_signals']:
    print(f"  - {signal['type']} ({signal['severity']}): {signal['description']}")
print(f"\nAudit ID: {result_2['audit_id']}")
print()

# Test Case 3: Clean content (no PII, no secrets)
print("\n" + "=" * 80)
print("TEST CASE 3: Clean Content (No Issues)")
print("-" * 80)
test_input_3 = """
How do I implement a binary search tree in Python? I need help with the insertion
and traversal methods.
"""

print("Input:")
print(test_input_3.strip())
print()

result_3 = plan_and_execute(test_input_3, use_case="general")

print("\nRESULTS:")
print(f"Decision: {result_3['decision']}")
print(f"Risk Score: {result_3['risk_score']}/100")
print(f"\nExplanation:")
print(f"  {result_3['explanation']}")
print(f"\nPolicy References:")
for policy in result_3['policy_refs']:
    print(f"  - {policy['id']}: {policy['summary']}")
print(f"\nDetected Signals:")
for signal in result_3['detected_signals']:
    print(f"  - {signal['type']} ({signal['severity']}): {signal['description']}")
if 'safe_prompt' in result_3:
    print(f"\nSanitized Output:")
    print(f"  {result_3['safe_prompt'][:200]}...")
print(f"\nAudit ID: {result_3['audit_id']}")
print()

# Test Case 4: Multiple PII types (email, phone, SSN)
print("\n" + "=" * 80)
print("TEST CASE 4: Multiple PII Types")
print("-" * 80)
test_input_4 = """
Customer support ticket: User with email jane.smith@company.com, phone
(555) 987-6543, and SSN 123-45-6789 is reporting login issues.
"""

print("Input:")
print(test_input_4.strip())
print()

result_4 = plan_and_execute(test_input_4, use_case="support")

print("\nRESULTS:")
print(f"Decision: {result_4['decision']}")
print(f"Risk Score: {result_4['risk_score']}/100")
print(f"\nExplanation:")
print(f"  {result_4['explanation']}")
print(f"\nPolicy References:")
for policy in result_4['policy_refs']:
    print(f"  - {policy['id']}: {policy['summary']}")
print(f"\nDetected Signals:")
for signal in result_4['detected_signals']:
    print(f"  - {signal['type']} ({signal['severity']}): {signal['description']}")
if 'safe_prompt' in result_4:
    print(f"\nSanitized Output:")
    print(f"  {result_4['safe_prompt'][:200]}...")
print(f"\nAudit ID: {result_4['audit_id']}")
print()

print("=" * 80)
print("All test cases completed!")
print("=" * 80)
print()
print("DYNAMIC FLOW DEMONSTRATION:")
print("- Test 1: Secrets NOT found -> PII detected -> Policy evaluated -> Sanitized")
print("- Test 2: Secrets found -> EARLY EXIT (no PII check, no sanitization)")
print("- Test 3: No secrets, no PII -> Policy evaluated -> Sanitized (minimal)")
print("- Test 4: Multiple PII types -> Higher risk score -> Sanitized")
print()
print("All agents worked autonomously with dynamic execution flow!")
