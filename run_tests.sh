#!/bin/bash

# Test runner script for Rust CLI Wallet
# Usage: ./run_tests.sh [option]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to run tests with different options
run_tests() {
    case "$1" in
        "unit")
            print_status "Running unit tests only..."
            cargo test --lib
            ;;
        "integration")
            print_status "Running integration tests only..."
            cargo test --test integration_tests
            ;;
        "all")
            print_status "Running all tests..."
            cargo test
            ;;
        "check")
            print_status "Running cargo check..."
            cargo check
            ;;
        "build")
            print_status "Building the project..."
            cargo build
            ;;
        "clean")
            print_status "Cleaning build artifacts..."
            cargo clean
            ;;
        "coverage")
            print_status "Running tests with coverage (requires cargo-tarpaulin)..."
            if command -v cargo-tarpaulin &> /dev/null; then
                cargo tarpaulin --out Html
                print_success "Coverage report generated in tarpaulin-report/index.html"
            else
                print_error "cargo-tarpaulin not found. Install with: cargo install cargo-tarpaulin"
                exit 1
            fi
            ;;
        "bench")
            print_status "Running benchmarks..."
            cargo bench
            ;;
        "doc")
            print_status "Generating documentation..."
            cargo doc --open
            ;;
        "clippy")
            print_status "Running clippy linter..."
            cargo clippy -- -D warnings
            ;;
        "fmt")
            print_status "Checking code formatting..."
            cargo fmt -- --check
            ;;
        "fmt-fix")
            print_status "Fixing code formatting..."
            cargo fmt
            ;;
        "help"|"")
            echo "Rust CLI Wallet Test Runner"
            echo "=========================="
            echo ""
            echo "Usage: $0 [option]"
            echo ""
            echo "Options:"
            echo "  unit       - Run unit tests only"
            echo "  integration- Run integration tests only"
            echo "  all        - Run all tests (default)"
            echo "  check      - Run cargo check"
            echo "  build      - Build the project"
            echo "  clean      - Clean build artifacts"
            echo "  coverage   - Run tests with coverage report"
            echo "  bench      - Run benchmarks"
            echo "  doc        - Generate and open documentation"
            echo "  clippy     - Run clippy linter"
            echo "  fmt        - Check code formatting"
            echo "  fmt-fix    - Fix code formatting"
            echo "  help       - Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 unit"
            echo "  $0 integration"
            echo "  $0 coverage"
            echo "  $0 clippy"
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Run '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Main execution
main() {
    print_status "Starting test runner for Rust CLI Wallet..."
    
    # Check if we're in the right directory
    if [ ! -f "Cargo.toml" ]; then
        print_error "Cargo.toml not found. Please run this script from the project root."
        exit 1
    fi
    
    # Run the specified tests
    run_tests "$1"
    
    if [ $? -eq 0 ]; then
        print_success "Tests completed successfully!"
    else
        print_error "Tests failed!"
        exit 1
    fi
}

# Execute main function
main "$1" 