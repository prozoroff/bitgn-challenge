"""
BitGN challenge harness client.
Connects to BitGN API, iterates tasks, runs agent, collects scores.
"""

import os
import sys
import textwrap
from pathlib import Path

from dotenv import load_dotenv

# Явный путь к .env рядом с main.py; override=True — иначе пустой BITGN_API_KEY в окружении
# перекрывает значение из файла (поведение python-dotenv по умолчанию).
load_dotenv(Path(__file__).resolve().parent / ".env", override=True)

from bitgn.harness_connect import HarnessServiceClientSync
from bitgn.harness_pb2 import (
    EndTrialRequest,
    EvalPolicy,
    GetBenchmarkRequest,
    StartRunRequest,
    StartTrialRequest,
    StatusRequest,
    SubmitRunRequest,
)
from connectrpc.errors import ConnectError

from agent import run_agent

BITGN_URL = os.getenv("BITGN_HOST") or os.getenv("BENCHMARK_HOST", "https://api.bitgn.com")
BITGN_API_KEY = (os.getenv("BITGN_API_KEY") or "").strip()
BENCHMARK_ID = os.getenv("BENCHMARK_ID", "bitgn/pac1-dev")
RUN_NAME = os.getenv("RUN_NAME", "PAC1 prozorov")
MODEL = os.getenv("MODEL", "gpt-4o")
MAX_STEPS = int(os.getenv("MAX_STEPS", "60"))

G = "\x1B[32m"
R = "\x1B[31m"
B = "\x1B[34m"
Y = "\x1B[33m"
C = "\x1B[0m"


def main() -> None:
    task_filter = sys.argv[1:]

    scores: list[tuple[str, float]] = []

    if not BITGN_API_KEY:
        print(
            f"{R}Нет BITGN_API_KEY: добавьте в agent/.env или экспортируйте ключ из профиля BitGN. "
            f"Если в shell задан пустой export, удалите его — иначе он мешал подхвату из .env.{C}"
        )
        sys.exit(1)

    try:
        client = HarnessServiceClientSync(BITGN_URL, api_key=BITGN_API_KEY)
        status = client.status(StatusRequest())
        print(f"Connected to BitGN: {status.status} v{status.version}")

        res = client.get_benchmark(GetBenchmarkRequest(benchmark_id=BENCHMARK_ID))
        policy = EvalPolicy.Name(res.policy)
        print(
            f"{policy} benchmark: {res.benchmark_id} "
            f"with {len(res.tasks)} tasks.\n{G}{res.description}{C}"
        )

        run = client.start_run(
            StartRunRequest(
                name=RUN_NAME,
                benchmark_id=BENCHMARK_ID,
                api_key=BITGN_API_KEY,
            )
        )

        try:
            for trial_id in run.trial_ids:
                trial = client.start_trial(StartTrialRequest(trial_id=trial_id))

                if task_filter and trial.task_id not in task_filter:
                    continue

                print(f"\n{'=' * 60}")
                print(f"TASK: {trial.task_id}")
                print(f"{'=' * 60}")

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
                    scores.append((trial.task_id, result.score))
                    style = G if result.score == 1 else R
                    explain = textwrap.indent("\n".join(result.score_detail), "  ")
                    print(f"\n{style}Score: {result.score:0.2f}{C}")
                    if explain.strip():
                        print(explain)

        finally:
            client.submit_run(SubmitRunRequest(run_id=run.run_id, force=True))

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
