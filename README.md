# ghidra-callgraph

Extract call graphs from compiled binaries using [Ghidra](https://ghidra-sre.org/) via [pyhidra](https://github.com/dod-cyber-crime-center/pyhidra).

## Requirements

- Python 3.10+
- Java: OpenJDK 21+
- Ghidra 11.2+ (set `GHIDRA_INSTALL_DIR` environment variable)

## Installation

```bash
pip install .
```

## Usage

```bash
# CLI
ghidra-callgraph -i /path/to/binary.so -o output.json -n library_name

# As a module
python -m ghidra_callgraph -i /path/to/binary.so -o output.json
```

### Options

```
-i, --input    Path to the input binary file (required)
-o, --output   Output JSON file path (prints to stdout if omitted)
-n, --name     Library name to include in the output JSON
-d, --dir      Directory for Ghidra project storage
-l, --log      Logging level (debug, info, warning, error, critical)
```

### Output format

```json
{
  "library": "library_name",
  "edges": [[0, 1], [1, 2]],
  "nodes": {
    "0": {"name": "main"},
    "1": {"name": "helper_func"},
    "2": {"name": "libc_call"}
  }
}
```

## License

AGPL-3.0-only
