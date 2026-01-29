# We cannot use $(shell pwd), which will return unix path format on Windows,
# making it hard to use.
cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

TOP := $(cur_dir)
# RUSTFLAGS that are likely to be tweaked by developers. For example,
# while we enable debug logs by default here, some might want to strip them
# for minimal code size / consumed cycles.
CUSTOM_RUSTFLAGS := -C debug-assertions
# Additional cargo args to append here. For example, one can use
# make test CARGO_ARGS="-- --nocapture" so as to inspect data emitted to
# stdout in unit tests
CARGO_ARGS :=
MODE := release
# Tweak this to change the clang version to use for building C code. By default
# we use a bash script with some heuristics to find clang in current system.
CLANG := $(shell $(TOP)/scripts/find_clang)
# When this is set, a single contract will be built instead of all contracts
CONTRACT :=
# By default, we would clean build/{release,debug} folder first, in case old
# contracts are mixed together with new ones, if for some reason you want to
# revert this behavior, you can change this to anything other than true
CLEAN_BUILD_DIR_FIRST := true
BUILD_DIR := build/$(MODE)

ifeq (release,$(MODE))
	MODE_ARGS := --release
endif

# Pass setups to child make processes
export CUSTOM_RUSTFLAGS
export TOP
export CARGO_ARGS
export MODE
export CLANG
export BUILD_DIR

default: build test

build:
	@if [ "x$(CLEAN_BUILD_DIR_FIRST)" = "xtrue" ]; then \
		echo "Cleaning $(BUILD_DIR) directory..."; \
		rm -rf $(BUILD_DIR); \
	fi
	mkdir -p $(BUILD_DIR)
	@set -eu; \
	if [ "x$(CONTRACT)" = "x" ]; then \
		for contract in $(wildcard contracts/*); do \
			$(MAKE) -e -C $$contract build; \
		done; \
		for crate in $(wildcard crates/*); do \
			cargo build -p $$(basename $$crate) $(MODE_ARGS) $(CARGO_ARGS); \
		done; \
		for sim in $(wildcard native-simulators/*); do \
			cargo build -p $$(basename $$sim) $(MODE_ARGS) $(CARGO_ARGS); \
		done; \
		for sim in $(wildcard native-simulators/*); do \
			simname=$$(basename $$sim); \
			libname=$$(echo $$simname | sed 's/-/_/g'); \
			if [ -f "target/$(MODE)/lib$${libname}.so" ]; then \
				cp "target/$(MODE)/lib$${libname}.so" $(BUILD_DIR)/; \
			fi; \
		done; \
	else \
		$(MAKE) -e -C contracts/$(CONTRACT) build; \
		cargo build -p $(CONTRACT)-sim $(MODE_ARGS); \
		simname=$(CONTRACT)-sim; \
		libname=$$(echo $$simname | sed 's/-/_/g'); \
		if [ -f "target/$(MODE)/lib$${libname}.so" ]; then \
			cp "target/$(MODE)/lib$${libname}.so" $(BUILD_DIR)/; \
		fi; \
	fi;

# Run a single make task for a specific contract. For example:
#
# make run CONTRACT=stack-reorder TASK=adjust_stack_size STACK_SIZE=0x200000
TASK :=
run:
	$(MAKE) -e -C contracts/$(CONTRACT) $(TASK)

# test, check, clippy and fmt here are provided for completeness,
# there is nothing wrong invoking cargo directly instead of make.
test:
	cargo test $(CARGO_ARGS)

check:
	cargo check $(CARGO_ARGS)

clippy:
	cargo clippy $(CARGO_ARGS)

fmt:
	cargo fmt $(CARGO_ARGS)

# Arbitrary cargo command is supported here. For example:
#
# make cargo CARGO_CMD=expand CARGO_ARGS="--ugly"
#
# Invokes:
# cargo expand --ugly
CARGO_CMD :=
cargo:
	cargo $(CARGO_CMD) $(CARGO_ARGS)

clean:
	rm -rf build
	cargo clean

TEMPLATE_TYPE := --git
TEMPLATE_REPO := https://github.com/cryptape/ckb-script-templates
CRATE :=
TEMPLATE := contract
DESTINATION := contracts
generate:
	@set -eu; \
	if [ "x$(CRATE)" = "x" ]; then \
		mkdir -p $(DESTINATION); \
		cargo generate $(TEMPLATE_TYPE) $(TEMPLATE_REPO) $(TEMPLATE) \
			--destination $(DESTINATION); \
		GENERATED_DIR=$$(ls -dt $(DESTINATION)/* | head -n 1); \
		if [ -f "$$GENERATED_DIR/.cargo-generate/tests.rs" ]; then \
			cat $$GENERATED_DIR/.cargo-generate/tests.rs >> tests/src/tests.rs; \
			rm -rf $$GENERATED_DIR/.cargo-generate/; \
		fi; \
		sed "s,@@INSERTION_POINT@@,@@INSERTION_POINT@@\n  \"$$GENERATED_DIR\"\,," Cargo.toml > Cargo.toml.new; \
		mv Cargo.toml.new Cargo.toml; \
	else \
		mkdir -p $(DESTINATION); \
		cargo generate $(TEMPLATE_TYPE) $(TEMPLATE_REPO) $(TEMPLATE) \
			--destination $(DESTINATION) \
			--name $(CRATE); \
		if [ -f "$(DESTINATION)/$(CRATE)/.cargo-generate/tests.rs" ]; then \
			cat $(DESTINATION)/$(CRATE)/.cargo-generate/tests.rs >> tests/src/tests.rs; \
			rm -rf $(DESTINATION)/$(CRATE)/.cargo-generate/; \
		fi; \
		sed '/@@INSERTION_POINT@@/s/$$/\n  "$(DESTINATION)\/$(CRATE)",/' Cargo.toml > Cargo.toml.new; \
		mv Cargo.toml.new Cargo.toml; \
	fi;

generate-native-simulator:
	@set -eu; \
	if [ -z "$(CRATE)" ]; then \
		echo "Error: Must have CRATE=<Contract Name>"; \
		exit 1; \
	fi; \
	mkdir -p native-simulators; \
	cargo generate $(TEMPLATE_TYPE) $(TEMPLATE_REPO) native-simulator \
		-n $(CRATE)-sim \
		--destination native-simulators; \
	sed '/@@INSERTION_POINT@@/s/$$/\n  "native-simulators\/$(CRATE)-sim",/' Cargo.toml > Cargo.toml.new; \
	mv Cargo.toml.new Cargo.toml; \
	if [ ! -f "contracts/$(CRATE)/Cargo.toml" ]; then \
		echo "Warning: This is a non-existent contract and needs to be processed manually"; \
		echo "		Otherwise compilation may fail."; \
	fi;

prepare:
	rustup target add riscv64imac-unknown-none-elf

# Generate checksum info for reproducible build
CHECKSUM_FILE := build/checksums-$(MODE).txt
checksum: build
	shasum -a 256 build/$(MODE)/* > $(CHECKSUM_FILE)

# ============================================================================
# Coverage targets (using native-simulator mode)
# ============================================================================
# 
# Coverage works by:
# 1. Building simulator .so files with LLVM coverage instrumentation
# 2. Running tests with native-simulator feature (executes contracts natively)
# 3. Simulator .so files call __llvm_profile_write_file() on unload to flush coverage
# 4. Using llvm-cov to generate reports from the profraw files
#
# Requirements: rustup component llvm-tools-preview

LLVM_TOOLS_DIR := $(shell rustc --print sysroot)/lib/rustlib/$(shell rustc -vV | grep host | cut -d' ' -f2)/bin
LLVM_PROFDATA := $(LLVM_TOOLS_DIR)/llvm-profdata
LLVM_COV := $(LLVM_TOOLS_DIR)/llvm-cov
COVERAGE_DIR := target/coverage
PROFRAW_PATTERN := $(COVERAGE_DIR)/profraw

# Build simulators with coverage instrumentation
# Uses RUSTFLAGS directly instead of cargo-llvm-cov wrapper for proper instrumentation
build-sim-cov:
	@echo "Building native simulators with coverage instrumentation..."
	@# First build the RISC-V contract binaries (these don't need coverage)
	$(MAKE) build MODE=debug CLEAN_BUILD_DIR_FIRST=true
	@# Clean simulator artifacts to force rebuild with coverage
	rm -f target/debug/deps/libct_info_type*.rlib target/debug/deps/libct_token_type*.rlib target/debug/deps/libstealth_lock*.rlib
	rm -f target/debug/libct_info_type_sim.so target/debug/libct_token_type_sim.so target/debug/libstealth_lock_sim.so
	@# Rebuild simulators with LLVM coverage instrumentation
	@echo "Rebuilding simulators with LLVM coverage instrumentation..."
	RUSTFLAGS="-C instrument-coverage --cfg=coverage" \
		cargo build -p ct-info-type-sim -p ct-token-type-sim -p stealth-lock-sim
	@# Copy the instrumented simulators to build/debug/
	@echo "Copying instrumented simulators to build/debug/..."
	cp target/debug/libct_info_type_sim.so build/debug/
	cp target/debug/libct_token_type_sim.so build/debug/
	cp target/debug/libstealth_lock_sim.so build/debug/
	@echo "Done! Instrumented simulators are in build/debug/"

# Build simulators for coverage (debug mode for better coverage data)
build-sim:
	@echo "Building native simulators for coverage..."
	$(MAKE) build MODE=debug CLEAN_BUILD_DIR_FIRST=true

# Internal target: run tests and collect coverage data
coverage-run-tests:
	@echo "Running tests with coverage (native-simulator mode)..."
	@mkdir -p $(COVERAGE_DIR)
	@rm -f $(PROFRAW_PATTERN)-*.profraw
	@# Run ct-info tests
	LLVM_PROFILE_FILE="$(CURDIR)/$(PROFRAW_PATTERN)-%p-%8m.profraw" \
		MODE=debug cargo test --features native-simulator --package tests \
		-- --test-threads=1 test_ct_info 2>&1 || true
	@# Run ct-token tests
	LLVM_PROFILE_FILE="$(CURDIR)/$(PROFRAW_PATTERN)-%p-%8m.profraw" \
		MODE=debug cargo test --features native-simulator --package tests \
		-- --test-threads=1 test_ct_token 2>&1 || true
	@# Run stealth-lock tests
	LLVM_PROFILE_FILE="$(CURDIR)/$(PROFRAW_PATTERN)-%p-%8m.profraw" \
		MODE=debug cargo test --features native-simulator --package tests \
		-- --test-threads=1 test_stealth 2>&1 || true
	@echo "Merging coverage data..."
	$(LLVM_PROFDATA) merge -sparse $(PROFRAW_PATTERN)-*.profraw -o $(COVERAGE_DIR)/coverage.profdata
	@# Clean up profraw files after merging
	@rm -f $(PROFRAW_PATTERN)-*.profraw
	@# Clean up stray default_*.profraw files created by child processes
	@rm -f $(CURDIR)/default_*.profraw

# Run tests with coverage and generate text report
coverage: build-sim-cov coverage-run-tests
	@echo ""
	@echo "=== Coverage Report ==="
	@$(LLVM_COV) report \
		-object build/debug/libct_info_type_sim.so \
		-object build/debug/libct_token_type_sim.so \
		-object build/debug/libstealth_lock_sim.so \
		-instr-profile=$(COVERAGE_DIR)/coverage.profdata \
		--ignore-filename-regex='\.cargo|rustc|rustlib'

# Generate HTML coverage report
coverage-html: build-sim-cov coverage-run-tests
	@echo "Generating HTML coverage report..."
	@mkdir -p $(COVERAGE_DIR)/html
	@$(LLVM_COV) show \
		-object build/debug/libct_info_type_sim.so \
		-object build/debug/libct_token_type_sim.so \
		-object build/debug/libstealth_lock_sim.so \
		-instr-profile=$(COVERAGE_DIR)/coverage.profdata \
		--ignore-filename-regex='\.cargo|rustc|rustlib' \
		--format=html --output-dir=$(COVERAGE_DIR)/html \
		--show-line-counts-or-regions --show-instantiations
	@echo "Coverage report generated at: $(COVERAGE_DIR)/html/index.html"

# Generate LCOV format for CI integration
coverage-lcov: build-sim-cov coverage-run-tests
	@echo "Generating LCOV coverage report..."
	@$(LLVM_COV) export \
		-object build/debug/libct_info_type_sim.so \
		-object build/debug/libct_token_type_sim.so \
		-object build/debug/libstealth_lock_sim.so \
		-instr-profile=$(COVERAGE_DIR)/coverage.profdata \
		--ignore-filename-regex='\.cargo|rustc|rustlib' \
		--format=lcov > $(COVERAGE_DIR)/lcov.info
	@echo "LCOV report generated at: $(COVERAGE_DIR)/lcov.info"

# Install llvm-tools if not present
coverage-install:
	@if ! rustup component list --installed | grep -q llvm-tools; then \
		echo "Installing llvm-tools-preview..."; \
		rustup component add llvm-tools-preview; \
	else \
		echo "llvm-tools-preview is already installed"; \
	fi

# Clean coverage artifacts
coverage-clean:
	rm -rf $(COVERAGE_DIR)

.PHONY: build test check clippy fmt cargo clean prepare checksum \
        build-sim build-sim-cov coverage-run-tests coverage coverage-html coverage-lcov coverage-install coverage-clean
