import { default as capi } from "./capi/script.js";
import { textSummary } from "./index.js";

export const options = {
  thresholds: {
    http_req_duration: ["p(90)<300"],
    checks: ["rate==1.0"],
  },
  scenarios: {
    capiScenario: {
      exec: "capiRun",
      executor: "per-vu-iterations",
      vus: 20,
      iterations: 5,
      maxDuration: "600s",
    },
  },
};

export function capiRun() {
  capi();
}

export function handleSummary(data) {
  return {
    stdout: textSummary(data, { indent: " ", enableColors: true }),
  };
}
