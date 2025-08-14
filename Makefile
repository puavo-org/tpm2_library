# Copyright (c) 2025 Opinsys Oy

.PHONY: test

TARGET_DIR := target
TARGET := $(TARGET_DIR)/libtpm2_protocol.rlib
TEST := $(TARGET_DIR)/runner

test: $(TEST)
	@echo "Running kselftests..."
	@./$(TEST)

$(TEST): $(TARGET) protocol/tests/runner.rs
	@echo "Compiling test runner..."
	@rustc protocol/tests/runner.rs --crate-name runner --edition=2021 --extern tpm2_protocol=$(TARGET) -L $(TARGET_DIR) -o $(TEST)

$(TARGET): $(wildcard protocol/src/*.rs)
	@echo "Compiling protocol library..."
	@mkdir -p $(TARGET_DIR)
	@rustc --crate-type lib --crate-name tpm2_protocol protocol/src/lib.rs --edition=2021 --out-dir $(TARGET_DIR)
