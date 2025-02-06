# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOBENCH=$(GOTEST) -bench=.

# C compiler settings
CC=gcc
CFLAGS=-Wall -Wextra -Wshadow -Wundef -O3 -fPIC

# Project structure
PROJECT_ROOT=$(shell pwd)
FALCON_C_DIR=$(PROJECT_ROOT)/c
FALCON_GO_DIR=$(PROJECT_ROOT)/falcon

# Object files except test_falcon.o and speed.o
C_OBJECTS=codec.o common.o falcon.o fft.o fpr.o keygen.o rng.o shake.o sign.o vrfy.o

# Benchmark parameters
BENCH_TIME?=2s
BENCH_COUNT?=5

# Ensure CGo is enabled
export CGO_ENABLED=1
export CC

.PHONY: all clean falcon test test_c test_go build bench_go bench_c run example

all: falcon example test

# Clean everything
clean:
	cd $(FALCON_C_DIR) && $(MAKE) clean
	rm -f $(FALCON_C_DIR)/speed $(FALCON_C_DIR)/test_falcon

# Build Falcon C implementation
falcon:
	cd $(FALCON_C_DIR) && CC=$(CC) CFLAGS="$(CFLAGS)" $(MAKE)

# Build and run C tests
test_c: falcon
	@echo "Building and running C tests..."
	cd $(FALCON_C_DIR) && $(CC) $(CFLAGS) -o test_falcon test_falcon.c $(C_OBJECTS)
	cd $(FALCON_C_DIR) && ./test_falcon
	cd $(FALCON_C_DIR) && ./test_keccak_prng

# Run Go tests
test_go: falcon
	@echo "Running Go tests..."
	CGO_CFLAGS="-I$(FALCON_C_DIR)" \
	$(GOTEST) ./falcon/...

# Run all tests
test: test_c test_go
	@echo "All tests completed."

# Run Go benchmarks
bench_go: falcon
	@echo "Running Go Falcon benchmarks..."
	CGO_CFLAGS="-I$(FALCON_C_DIR)" \
	$(GOBENCH) -benchtime=$(BENCH_TIME) -count=$(BENCH_COUNT) -benchmem ./falcon/...

# Build and run C benchmarks
bench_c: falcon
	@echo "Building C speed test..."
	cd $(FALCON_C_DIR) && $(CC) $(CFLAGS) -o speed speed.c $(C_OBJECTS)
	@echo "Running C Falcon benchmarks..."
	cd $(FALCON_C_DIR) && ./speed 2.0

# Build example
example: falcon
	CGO_CFLAGS="-I$(PROJECT_ROOT)/c" \
	CGO_LDFLAGS="-L$(PROJECT_ROOT)/c" \
	$(GOBUILD) -o examples/falcon-example examples/main.go

# Run example
run: example
	LD_LIBRARY_PATH=$(FALCON_C_DIR) ./examples/falcon-example