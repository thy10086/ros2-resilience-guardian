"""ARTEX-inspired bounded review: explicit fixture or configured model mode."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ros2_ws/src/guardian_core")]


def main(argv=None):
    from experiments.agent_review.contracts import strict_loads, make_bundle
    from experiments.agent_review.orchestration import run_review, MAX_INPUT
    parser = argparse.ArgumentParser(description=__doc__)
    sources = parser.add_mutually_exclusive_group(required=True)
    sources.add_argument("--sample", action="store_true", help="self-owned virtual Guardian model")
    sources.add_argument("--input", type=Path, help="strict files/frames JSON; never executed")
    parser.add_argument("--output", type=Path, required=True, help="new report file; existing files refused")
    parser.add_argument("--provider", choices=("fixture", "llm"), default="fixture")
    parser.add_argument("--base-url", help="OpenAI-compatible base URL or Chat Completions URL")
    parser.add_argument("--model", help="provider model identifier")
    parser.add_argument("--api-key-env", default="GUARDIAN_AGENT_API_KEY", help="name of credential environment variable; never the Key itself")
    parser.add_argument("--timeout", type=float, help="run deadline: fixture <=30s, llm <=180s")
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise ValueError("output already exists")
        if args.sample:
            payload = {"sample": "guardian_recovery_virtual_model"}
        else:
            with args.input.open("rb") as stream:
                raw = stream.read(MAX_INPUT + 1)
            if len(raw) > MAX_INPUT:
                raise ValueError("input limit exceeded")
            payload = strict_loads(raw.decode("utf-8"))
        # Validate raw bytes and envelope before spawning any registered tests.
        make_bundle(payload)
        provider = None
        if args.provider == "llm":
            import os
            from experiments.agent_review.provider import OpenAICompatibleProvider
            if not args.base_url or not args.model:
                raise ValueError("llm mode requires --base-url and --model")
            provider = OpenAICompatibleProvider(base_url=args.base_url,
                api_key=os.environ.get(args.api_key_env, ""), model=args.model)
        elif args.base_url or args.model:
            raise ValueError("base URL/model require explicit --provider llm")
        report = run_review(payload, provider=provider,
            timeout_sec=args.timeout if args.timeout is not None else (180 if provider else 30))
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, allow_nan=False, indent=2)
            stream.write("\n")
        print(json.dumps({"execution_status": report["execution_status"], "detection": report["detection"],
                          "provider_mode": report["provider_mode"], "tests": len(report["executions"])}))
        return 0 if report["execution_status"] == "COMPLETE" and report["detection"] == "NO_VIOLATIONS" else 1
    except (ValueError, OSError, UnicodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
