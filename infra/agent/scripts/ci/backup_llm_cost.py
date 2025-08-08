import sys
import json

from pathlib import Path

from shellphish_crs_utils.telemetry import Telemetry

if __name__ == "__main__":
    assert len(sys.argv) == 2

    out_path = Path(sys.argv[1])
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print("Collecting LLM cost data...")
    try:
        data = Telemetry.get_llm_cost_by_component()
    except Exception as e:
        print(f"Failed to collect LLM cost data: {e}")
        data = {}
    out_path.write_text(json.dumps(data, indent=2))