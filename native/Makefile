# HyperTraceX Native Module Compilation
# Compiles C++ modules for high-performance forensic operations

CXX = g++
CXXFLAGS = -O3 -Wall -fPIC -std=c++17
LDFLAGS = -shared

# Target modules
MODULES = raw_reader.so mft_parser.so

# Source files
RAW_READER_SRC = raw_reader.cpp
MFT_PARSER_SRC = mft_parser.cpp

# Object files
RAW_READER_OBJ = raw_reader.o
MFT_PARSER_OBJ = mft_parser.o

# Default target
all: $(MODULES)
	@echo "[+] All native modules compiled successfully"
	@echo ""
	@echo "Modules available:"
	@ls -la *.so 2>/dev/null || echo "  No modules compiled"

# Compile raw disk reader
raw_reader.so: $(RAW_READER_SRC)
	@echo "[*] Compiling Raw Disk Reader..."
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $<
	@echo "[+] raw_reader.so compiled"

# Compile MFT parser
mft_parser.so: $(MFT_PARSER_SRC)
	@echo "[*] Compiling MFT Parser..."
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $<
	@echo "[+] mft_parser.so compiled"

# Compile standalone test for raw reader
raw_reader_test: $(RAW_READER_SRC)
	@echo "[*] Compiling Raw Disk Reader (standalone test)..."
	$(CXX) $(CXXFLAGS) -DSTANDALONE_TEST -o $@ $<
	@echo "[+] raw_reader_test compiled"

# Compile standalone test for MFT parser
mft_parser_test: $(MFT_PARSER_SRC)
	@echo "[*] Compiling MFT Parser (standalone test)..."
	$(CXX) $(CXXFLAGS) -DSTANDALONE_TEST -o $@ $<
	@echo "[+] mft_parser_test compiled"

# Compile all standalone tests
tests: raw_reader_test mft_parser_test
	@echo "[+] All tests compiled"

# Clean compiled files
clean:
	@echo "[*] Cleaning compiled files..."
	rm -f *.so *.o raw_reader_test mft_parser_test
	@echo "[+] Clean complete"

# Install modules
install: all
	@echo "[*] Installing native modules..."
	cp *.so ../modules/ 2>/dev/null || mkdir -p ../modules && cp *.so ../modules/
	@echo "[+] Modules installed to ../modules/"

# Show help
help:
	@echo "HyperTraceX Native Module Compilation"
	@echo "=================================="
	@echo ""
	@echo "Targets:"
	@echo "  all        - Compile all shared libraries"
	@echo "  tests      - Compile standalone tests"
	@echo "  clean      - Remove compiled files"
	@echo "  install    - Install modules"
	@echo "  help       - Show this help"
	@echo ""
	@echo "Modules:"
	@echo "  raw_reader.so  - High-performance raw disk reader"
	@echo "  mft_parser.so  - NTFS Master File Table parser"
	@echo ""
	@echo "Usage:"
	@echo "  make all       # Compile everything"
	@echo "  make clean     # Clean up"
	@echo "  make install   # Install modules"

.PHONY: all clean install help tests
