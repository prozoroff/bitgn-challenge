"""
BitGN PAC Harness Client.
Connects to BitGN API, iterates tasks, runs agent, collects scores.
"""

import os
import sys
import textwrap

from dotenv import load_dotenv
from bitgn.harness_connect import HarnessServiceClientSync
from bitgn.harness_pb2 import (
    EndTrialRequest,
    EvalPolicy,
    GetBenchmarkRequest,
    StartPlaygroundRequest,
    StartRunRequest,
    StartTrialRequest,
    StatusRequest,
)
from connectrpc.errors import ConnectError

from agent import run_agent

load_dotenv()

BITGN_URL = os.getenv("BENCHMARK_HOST", "https://api.bitgn.com")
BENCHMARK_ID = os.getenv("BENCHMARK_ID", "bitgn/pac1-dev")
MODEL = os.getenv("MODEL", "gpt-4o")
MAX_STEPS = int(os.getenv("MAX_STEPS", "40"))

G = "\x1B[32m"
R = "\x1B[31m"
B = "\x1B[34m"
Y = "\x1B[33m"
C = "\x1B[0m"


def main() -> None:
    task_filter = sys.argv[1:]

    scores: list[tuple[str, float]] = []

    try:
        client = HarnessServiceClientSync(BITGN_URL)
        status = client.status(StatusRequest())
        print(f"Connected to BitGN: {status.status} v{status.version}")

        res = client.get_benchmark(GetBenchmarkRequest(benchmark_id=BENCHMARK_ID))
        policy = EvalPolicy.Name(res.policy)
        print(
            f"{policy} benchmark: {res.benchmark_id} "
            f"with {len(res.tasks)} tasks.\n{G}{res.description}{C}"
        )

        for task in res.tasks:
            if task_filter and task.task_id not in task_filter:
                continue

            print(f"\n{'=' * 60}")
            print(f"TASK: {task.task_id}")
            print(f"{'=' * 60}")

            trial = client.start_playground(
                StartPlaygroundRequest(
                    benchmark_id=BENCHMARK_ID,
                    task_id=task.task_id,
                )
            )

            print(f"{B}{trial.instruction}{C}")
            print(f"{'-' * 60}")

            try:
                run_agent(
                    harness_url=trial.harness_url,
                    task_text=trial.instruction,
                    model=MODEL,
                    max_steps=MAX_STEPS,
                )
            except Exception as exc:
                print(f"{R}AGENT ERROR{C}: {exc}")

            result = client.end_trial(EndTrialRequest(trial_id=trial.trial_id))

            if result.score is not None and result.score >= 0:
                scores.append((task.task_id, result.score))
                style = G if result.score == 1 else R
                explain = textwrap.indent("\n".join(result.score_detail), "  ")
                print(f"\n{style}Score: {result.score:0.2f}{C}")
                if explain.strip():
                    print(explain)

    except ConnectError as exc:
        print(f"{R}{exc.code}: {exc.message}{C}")
    except KeyboardInterrupt:
        print(f"\n{Y}Interrupted{C}")

    if scores:
        print(f"\n{'=' * 60}")
        print("RESULTS")
        print(f"{'=' * 60}")
        for task_id, score in scores:
            style = G if score == 1 else R
            print(f"  {task_id}: {style}{score:0.2f}{C}")

        total = sum(s for _, s in scores) / len(scores) * 100.0
        print(f"\nFINAL: {total:0.2f}%")


if __name__ == "__main__":
    main()
