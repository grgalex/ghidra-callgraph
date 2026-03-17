"""CLI entry point for ghidra-callgraph."""

import argparse
import json
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Extract a call graph from a compiled binary using Ghidra."
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Path to the input binary file",
    )
    parser.add_argument(
        "-d", "--dir", default=None,
        help="Directory for Ghidra project storage",
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output JSON file path (prints to stdout if omitted)",
    )
    parser.add_argument(
        "-n", "--name", default=None,
        help="Library full path to include in the 'library' field of the output JSON",
    )
    parser.add_argument(
        "-l", "--log", default="info",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Logging level (default: info)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log.upper()),
        format="%(asctime)s %(module)s:%(lineno)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    from ghidra_callgraph.generator import CallGraphGenerator

    bin_path = Path(args.input)
    if args.dir is not None:
        project_location = os.path.join(args.dir, ".ghidra_projects")
    else:
        project_location = Path(".ghidra_projects")

    generator = CallGraphGenerator(
        bin_path, project_location, bin_path.name, args.name
    )
    result = generator.generate()

    if args.output is None:
        print(json.dumps(result, indent=2))
    else:
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w") as f:
            f.write(json.dumps(result, indent=2))
        log.info(f"Wrote call graph to {args.output}")


if __name__ == "__main__":
    main()
