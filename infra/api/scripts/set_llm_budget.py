#! /usr/bin/env python3

import os
import sys
import json

OPENAI_BUDGET   = os.getenv("OPENAI_BUDGET", 40)
CLAUDE_BUDGET   = os.getenv("CLAUDE_BUDGET", 50)
GEMINI_BUDGET   = os.getenv("GEMINI_BUDGET", 0.000001)
GRAMMAR_BUDGET  = os.getenv("GRAMMAR_BUDGET", 50)
GRAMMAR_BUDGET_OPENAI = os.getenv("GRAMMAR_BUDGET_OPENAI", 10)
PATCHING_BUDGET = os.getenv("PATCHING_BUDGET", 0)

TOTAL_LLM_TIME_MINUTES = os.getenv("TOTAL_LLM_TIME_MINUTES", 1000)
TOTAL_LLM_TIME_MINUTES = int(TOTAL_LLM_TIME_MINUTES)

ROLLING_PERIOD_MINUTES = os.getenv("ROLLING_PERIOD_MINUTES", 1)
ROLLING_PERIOD_MINUTES = int(ROLLING_PERIOD_MINUTES)

FULL_MODE_TASKS = os.getenv("FULL_MODE_TASKS", 6)
FULL_MODE_TASKS = int(FULL_MODE_TASKS)

DELTA_MODE_TASKS = os.getenv("DELTA_MODE_TASKS", 9)
DELTA_MODE_TASKS = int(DELTA_MODE_TASKS)

FULL_MODE_TASK_LENGTH_MINUTES = os.getenv("FULL_MODE_TASK_LENGTH_MINUTES", 24*60)
FULL_MODE_TASK_LENGTH_MINUTES = int(FULL_MODE_TASK_LENGTH_MINUTES)

DELTA_MODE_TASK_LENGTH_MINUTES = os.getenv("DELTA_MODE_TASK_LENGTH_MINUTES", 8*60)
DELTA_MODE_TASK_LENGTH_MINUTES = int(DELTA_MODE_TASK_LENGTH_MINUTES)

budget_config = {
    "budgets": {},
    "period_minutes": ROLLING_PERIOD_MINUTES,
    "task_counts": {
        "full": FULL_MODE_TASKS,
        "delta": DELTA_MODE_TASKS,
    },
    "task_lengths": {
        "full": FULL_MODE_TASK_LENGTH_MINUTES,
        "delta": DELTA_MODE_TASK_LENGTH_MINUTES,
    },
}

def set_llm_budget(name, budget):
    budget = float(budget)
    budget_config["budgets"][name] = {
        "max_budget": budget
    }

BUDGET_CONFIG_PATH = "/shared/llm_budget_manager_config.json"
BUDGET_STATE_PATH = "/shared/llm_budget_manager_state.json"

def save_budget_config():
    with open(BUDGET_CONFIG_PATH, "w") as f:
        json.dump(budget_config, f)

def reset_spend_state():
    try:
        os.remove(BUDGET_STATE_PATH)
    except FileNotFoundError:
        pass

set_llm_budget("openai", OPENAI_BUDGET)
set_llm_budget("claude", CLAUDE_BUDGET)
set_llm_budget("gemini", GEMINI_BUDGET)

set_llm_budget("grammar", GRAMMAR_BUDGET)
set_llm_budget("grammar-openai", GRAMMAR_BUDGET_OPENAI)
set_llm_budget("patching", PATCHING_BUDGET)

save_budget_config()

reset_spend_state()
