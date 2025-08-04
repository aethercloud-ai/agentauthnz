#!/usr/bin/env python3
"""
Test Runner for OAuth2/OIDC Library Unit Tests

This script provides a convenient way to run unit tests with various options
including different output formats, test filtering, and coverage reporting.
"""

import sys
import os
import argparse
import unittest
import subprocess
from pathlib import Path


def run_basic_tests(verbosity=2, pattern=None):
    """Run basic unit tests."""
    print("Running OAuth2/OIDC Library Unit Tests")
    print("=" * 60)
    
    # Add the current directory to Python path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    # Discover and run tests
    loader = unittest.TestLoader()
    
    if pattern:
        loader.testNamePatterns = [pattern]
    
    # Load test modules
    test_modules = [
        'test_agentauth',
        'test_agentauth_security',
    ]
    
    suite = unittest.TestSuite()
    for module_name in test_modules:
        try:
            module = __import__(module_name)
            tests = loader.loadTestsFromModule(module)
            suite.addTests(tests)
        except ImportError as e:
            print(f"Warning: Could not import {module_name}: {e}")
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    
    return result


def run_with_coverage():
    """Run tests with coverage reporting."""
    try:
        import coverage
    except ImportError:
        print("Coverage package not installed. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "coverage"])
        import coverage
    
    print("Running tests with coverage...")
    
    # Start coverage
    cov = coverage.Coverage()
    cov.start()
    
    # Run tests
    result = run_basic_tests(verbosity=1)
    
    # Stop coverage and generate report
    cov.stop()
    cov.save()
    
    print("\n" + "=" * 60)
    print("Coverage Report")
    print("=" * 60)
    
    # Generate coverage report
    cov.report()
    
    # Generate HTML report
    cov.html_report(directory='htmlcov')
    print(f"\nHTML coverage report generated in 'htmlcov' directory")
    
    return result


def run_specific_test(test_name):
    """Run a specific test by name."""
    print(f"Running specific test: {test_name}")
    print("=" * 60)
    
    # Add the current directory to Python path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    # Create test suite with specific test
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    
    # Try to load the specific test
    try:
        test = loader.loadTestsFromName(test_name)
        suite.addTest(test)
    except Exception as e:
        print(f"Error loading test '{test_name}': {e}")
        return None
    
    # Run the test
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


def run_performance_tests():
    """Run performance-focused tests."""
    print("Running Performance Tests")
    print("=" * 60)
    
    # Import and run performance tests
    try:
        from test_agentauth_lib_unit import TestIntegrationScenarios
        
        suite = unittest.TestSuite()
        loader = unittest.TestLoader()
        
        # Add performance-related tests
        performance_tests = [
            'test_full_authentication_flow',
            'test_client_with_custom_timeout_and_ttl',
            'test_client_with_scope'
        ]
        
        for test_name in performance_tests:
            test = loader.loadTestsFromName(f"test_agentauth_lib_unit.TestIntegrationScenarios.{test_name}")
            suite.addTest(test)
        
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        return result
        
    except ImportError as e:
        print(f"Error importing performance tests: {e}")
        return None


def run_error_handling_tests():
    """Run error handling tests."""
    print("Running Error Handling Tests")
    print("=" * 60)
    
    # Import and run error handling tests
    try:
        from test_agentauth_lib_unit import (
            TestOAuth2OIDCError,
            TestErrorMessages
        )
        
        suite = unittest.TestSuite()
        loader = unittest.TestLoader()
        
        # Add error handling tests
        error_test_classes = [
            TestOAuth2OIDCError,
            TestErrorMessages
        ]
        
        for test_class in error_test_classes:
            tests = loader.loadTestsFromTestCase(test_class)
            suite.addTests(tests)
        
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        return result
        
    except ImportError as e:
        print(f"Error importing error handling tests: {e}")
        return None


def generate_test_report(result):
    """Generate a detailed test report."""
    print("\n" + "=" * 60)
    print("Test Report Summary")
    print("=" * 60)
    
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped) if hasattr(result, 'skipped') else 0
    passed = total_tests - failures - errors - skipped
    
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed}")
    print(f"Failed: {failures}")
    print(f"Errors: {errors}")
    print(f"Skipped: {skipped}")
    
    if total_tests > 0:
        success_rate = (passed / total_tests) * 100
        print(f"Success Rate: {success_rate:.1f}%")
    
    if failures:
        print(f"\nFailures:")
        for test, traceback in result.failures:
            print(f"  {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if errors:
        print(f"\nErrors:")
        for test, traceback in result.errors:
            print(f"  {test}: {traceback.split('Exception:')[-1].strip()}")
    
    return {
        'total': total_tests,
        'passed': passed,
        'failed': failures,
        'errors': errors,
        'skipped': skipped,
        'success_rate': success_rate if total_tests > 0 else 0
    }


def main():
    """Main function to parse arguments and run tests."""
    parser = argparse.ArgumentParser(
        description="Run OAuth2/OIDC Library Unit Tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_tests.py                    # Run all tests
  python run_tests.py --verbose          # Run with verbose output
  python run_tests.py --coverage         # Run with coverage report
  python run_tests.py --pattern "*Error*" # Run tests matching pattern
  python run_tests.py --performance      # Run performance tests only
  python run_tests.py --errors           # Run error handling tests only
  python run_tests.py --test "TestOAuth2OIDCClient.test_client_initialization_success"
        """
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '--coverage',
        action='store_true',
        help='Run tests with coverage reporting'
    )
    
    parser.add_argument(
        '--pattern', '-p',
        type=str,
        help='Pattern to match test names'
    )
    
    parser.add_argument(
        '--performance',
        action='store_true',
        help='Run performance tests only'
    )
    
    parser.add_argument(
        '--errors',
        action='store_true',
        help='Run error handling tests only'
    )
    
    parser.add_argument(
        '--test', '-t',
        type=str,
        help='Run a specific test by name'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        choices=['text', 'json', 'xml'],
        default='text',
        help='Output format for test results'
    )
    
    args = parser.parse_args()
    
    # Set verbosity
    verbosity = 2 if args.verbose else 1
    
    try:
        # Run appropriate tests based on arguments
        if args.test:
            result = run_specific_test(args.test)
        elif args.performance:
            result = run_performance_tests()
        elif args.errors:
            result = run_error_handling_tests()
        elif args.coverage:
            result = run_with_coverage()
        else:
            result = run_basic_tests(verbosity=verbosity, pattern=args.pattern)
        
        if result:
            # Generate report
            report = generate_test_report(result)
            
            # Exit with appropriate code
            if report['failed'] > 0 or report['errors'] > 0:
                sys.exit(1)
            else:
                sys.exit(0)
        else:
            print("No tests were run.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nTest execution interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error running tests: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main() 