#! /usr/bin/env python3

# This script will run a rolling budget which limits how much llm usage per budget can be done in a unit of time

import sys
import os
import time
import json
import math
import requests
from typing import Dict
from filelock import FileLock, Timeout

INITIAL_BUDGET = .145

'''
{
    "budgets": {
        "atest": {
            "per_period": 0.1,
            "max_budget": 10
        }
    },
    "period_minutes": 1
}
'''

# TODO(finaldeploy) Set this to 5
NUM_UNHARNESSED_TASKS = 5

ROLLING_PERIOD = 1

BUDGET_CONFIG_PATH = "/shared/llm_budget_manager_config.json"
BUDGET_STATE_PATH = "/shared/llm_budget_manager_state.json"
BONUS_BUDGET_PATH = "/shared/llm_budget_bonus.json"

TASK_POOL_STATE_FILE = "/shared/task_pool_state.json"
TASK_POOL_STATE_LOCK = "/shared/task_pool_state.lock"

LITELLM_ENDPOINT = os.getenv("AIXCC_LITELLM_HOSTNAME", "http://litellm:4000")
LITELLM_KEY = os.getenv("LITELLM_KEY", "sk-artiphishell-da-best!!!")

def wait_until_litellm_running():
    while True:
        try:
            response = requests.get(f"{LITELLM_ENDPOINT}/health", headers={
                "Authorization": f"Bearer {LITELLM_KEY}",
            })
            if response.status_code == 200:
                break
            data = response.json()
            if data.get("healthy_count", 0) > 5:
                break
        except Exception as e:
            print(f"🎟️ Waiting for litellm to be running: {e}")
        time.sleep(5)


def get_config():
    while True:
        if not os.path.exists(BUDGET_CONFIG_PATH):
            print("Budget config file not found, waiting until it is created")
            time.sleep(5)
            continue
        break

    with open(BUDGET_CONFIG_PATH, "r") as f:
        return json.load(f)

def get_state():
    if not os.path.exists(BUDGET_STATE_PATH):
        return {
            "start_time": None,
            "end_time": None,
            "last_roll": 0,
            "budget_ids": {},
            "last_budget_amounts": {}
        }

    with open(BUDGET_STATE_PATH, "r") as f:
        return json.load(f)

def get_bonus_state():
    if not os.path.exists(BONUS_BUDGET_PATH):
        return []

    with open(BONUS_BUDGET_PATH, "r") as f:
        return json.load(f)

def save_state(state):
    with open(BUDGET_STATE_PATH+'.tmp', "w") as f:
        json.dump(state, f)

    os.rename(BUDGET_STATE_PATH+'.tmp', BUDGET_STATE_PATH)


def get_user_info(name):
    '''
    curl -s 'http://litellm:4000/customer/info?end_user_id=asdf' \
--header 'Authorization: Bearer sk-artiphishell-da-best!!!' \
-v
    '''
    if not '-budget' in name:
        name = f"{name}-budget"

    response = requests.get(
        f"{LITELLM_ENDPOINT}/customer/info?end_user_id={name}",
        headers={
            "Authorization": f"Bearer {LITELLM_KEY}",
        }
    )
    if response.status_code == 200:
        return response.json()
    print(f"🤡 Failed to get user info for {name}: {response.text}")
    return None

def create_user_if_not_exists(name):
    if not '-budget' in name:
        name = f"{name}-budget"

    try:
        user_info = get_user_info(name)
        if user_info:
            return user_info
    except Exception as e:
        pass
    try:
        response = requests.post(
            f"{LITELLM_ENDPOINT}/customer/new",
            headers={
                "Authorization": f"Bearer {LITELLM_KEY}",
            },
            json={"user_id": name}
        )
    except Exception as e:
        pass

def assign_budget_to_user(name, budget_id):
    '''
    curl -s 'http://litellm:4000/customer/update' \
--header 'Authorization: Bearer sk-artiphishell-da-best!!!' \
--header 'Content-Type: application/json' \
--data-raw '{
  "user_id": "asdf",
  "budget_id": "4c6b5844-a521-4c4e-977e-a20b0413df3b"
}' -v
    '''

    if not '-budget' in name:
        name = f"{name}-budget"

    create_user_if_not_exists(name)

    response = requests.post(
        f"{LITELLM_ENDPOINT}/customer/update",
        headers={
            "Authorization": f"Bearer {LITELLM_KEY}",
        },
        json={
            "user_id": name,
            "budget_id": budget_id
        }
    )
    if response.status_code != 200:
        raise Exception(f"Failed to update customer: {response.text}")

def create_new_budget(name, current_value):
    '''
    curl -s 'http://litellm:4000/budget/new' \
--header 'Authorization: Bearer sk-artiphishell-da-best!!!' \
--header 'Content-Type: application/json' \
--data-raw '{
  "max_budget": 0.1,
  "budget_duration": "30d"
    }' -v
    '''
    response = requests.post(
        f"{LITELLM_ENDPOINT}/budget/new",
        headers={
            "Authorization": f"Bearer {LITELLM_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "max_budget": current_value,
            "budget_duration": "30d"
        }
    )
    if response.status_code != 200:
        raise Exception(f"Failed to create new budget: {response.text}")

    budget_id = response.json()["budget_id"]

    assign_budget_to_user(f"{name}-budget", budget_id)

    return budget_id

def get_budget_info(budget_id):
    response = requests.get(
        f"{LITELLM_ENDPOINT}/budget/list",
        headers={
            "Authorization": f"Bearer {LITELLM_KEY}",
        }
    )
    if response.status_code != 200:
        print(f"🤡 Failed to list budgets: {response.text}")
        return None
    
    budgets = response.json()
    for budget in budgets:
        if budget.get("budget_id") == budget_id:
            return budget
    return None

def block_user(user_id):
    print(f"🅱️🔨 Blocking user {user_id} !!!")
    '''
    curl -s 'http://litellm:4000/customer/block' \
--header 'Authorization: Bearer sk-artiphishell-da-best!!!' \
--header 'Content-Type: application/json' \
--data-raw '{
  "user_ids": ["asdf"]
}' -v
    '''
    if not '-budget' in user_id:
        user_id = f"{user_id}-budget"

    response = requests.post(
        f"{LITELLM_ENDPOINT}/customer/block",
        headers={
            "Authorization": f"Bearer {LITELLM_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "user_ids": [user_id]
        }
    )
    if response.status_code != 200:
        print(f"🤡 Failed to block user {user_id}: {response.text}")
        return False
    return True

def sanity_check_budget(user_id, budget_id, expected_max_budget):
    if not '-budget' in user_id:
        user_id = f"{user_id}-budget"

    # Make sure the user is using the assigned budget
    for i in range(10):
        user_info = get_user_info(user_id)
        if user_info:
            break
        print(f"🤡 Failed to find user {user_id}, attempting to recreate it!!")
        create_user_if_not_exists(user_id)
        time.sleep(3)
    else:
        print(f"🤡 Failed to find user {user_id} after 10 attempts")
        block_user(user_id)


    for i in range(10):
        budget_info = get_budget_info(budget_id)
        if budget_info:
            break
        print(f"🤡 Failed to find budget {budget_id}, attempting to recreate it!!")
        budget_id = create_new_budget(user_id, expected_max_budget)
        time.sleep(3)

    if not budget_info:
        print(f"🤡 Failed to find budget {budget_id} after 10 attempts")
        block_user(user_id)
        return

    for i in range(10):
        budget_info = get_budget_info(budget_id)
        if budget_info.get("max_budget") - expected_max_budget < 0.02:
            break
        print(f"🤡 Budget {budget_id} has max budget {budget_info.get('max_budget')} but expected {expected_max_budget}")
        update_budget(budget_id, expected_max_budget)
        time.sleep(1)
    else:
        print(f"🤡 Failed to update budget {budget_id} after 10 attempts")
        block_user(user_id)
    
    assign_budget_to_user(user_id, budget_id)
    update_budget(budget_id, expected_max_budget)

    # TODO track if the user's spending was reset!!!!

    return budget_id




    

def update_budget(budget_id, per_period):
    '''
    curl -s 'http://litellm:4000/budget/update' \
--header 'Authorization: Bearer sk-artiphishell-da-best!!!' \
--header 'Content-Type: application/json' \
--data-raw '{
    "budget_id": "4c6b5844-a521-4c4e-977e-a20b0413df3b",
    "max_budget": 0.1
}' -v
    '''
    response = requests.post(
        f"{LITELLM_ENDPOINT}/budget/update",
        headers={
            "Authorization": f"Bearer {LITELLM_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "budget_id": budget_id,
            "max_budget": per_period
        }
    )
    if response.status_code != 200:
        raise Exception(f"Failed to update budget: {response.text}")

    return response.json()


from contextlib import contextmanager

@contextmanager
def optional_filelock(lock_path, timeout=10, max_retries=3, retry_delay=0.1):
    """
    best-effort file lock. tries to acquire, but continues anyway if it can't.
    
    useful for resource optimizations where locking is preferred but not required.
    """
    retries = 0
    lock = FileLock(lock_path, timeout=timeout)
    
    while retries < max_retries:
        try:
            with lock:
                yield True  # indicates we got the lock
                return
        except Timeout:
            retries += 1
            if retries >= max_retries:
                break
            
            # attempt to remove potentially stale lock
            try:
                os.remove(lock_path)
                time.sleep(retry_delay)
            except:
                pass
    
    # couldn't get lock, but continue anyway
    yield False  # indicates we're proceeding without lock

def get_active_tasks():
    with optional_filelock(TASK_POOL_STATE_LOCK, timeout=60) as got_lock:
        if not got_lock:
            print(f"🤡 Couldn't acquire lock for {TASK_POOL_STATE_LOCK}, proceeding anyway")

        if not os.path.exists(TASK_POOL_STATE_FILE):
            return []

        try:
            with open(TASK_POOL_STATE_FILE, "r") as f:
                tasks: Dict[str, Dict] = json.load(f)

            now = time.time()

            active_tasks = []

            for _,task in tasks.items():
                if task.get("deadline",0) < now:
                    continue

                active_tasks.append(task)

            return active_tasks

        except Exception as e:
            print(f"⚠️⚠️ Error getting active tasks: {e}")
            return []

class BudgetManager:
    def __init__(self, config, state):
        self.config = config
        self.state = state

    def get_rolling_period_seconds(self):
        return self.config.get("period_minutes", ROLLING_PERIOD) * 60

    def get_rolling_period_minutes(self):
        return self.config.get("period_minutes", ROLLING_PERIOD)

    def add_seen_target(self, target_id, target_data):
        seen_targets = self.get_seen_targets()
        if target_id in seen_targets:
            return
        seen_targets[target_id]= target_data
        print(f"👀 New target {target_id} = {target_data}")

    def get_seen_targets(self):
        seen = self.state.get("seen_targets")
        if not seen:
            seen = {}
            self.state["seen_targets"] = seen
        return seen

    def calculate_budget_increases_percentage_of_total_budget(self):
        # To determine what % of the total budget should be added for each tick
        # This is calculated based on the number of active projects at this very moment.
        # Every task will have a per-period budget based on the length of the task

        # This function will return a percent of the total budget for the given period
        # IT IS NOT THE PERCENT OF THE PERIOD, IT IS THE PERCENT OF THE TOTAL BUDGET

        task_counts = self.config["task_counts"]

        total_num_tasks = task_counts["full"] + task_counts["delta"] - NUM_UNHARNESSED_TASKS

        weighted_task_count = 0
        try:
            weighted_task_count = ((task_counts["full"] - 2) * 2) + (task_counts["delta"] - 3)
        except Exception as e:
            pass

        # This represents the percentage of the TOTAL BUDGET that each task gets
        total_budget_for_task = 1.0 / total_num_tasks

        try:
            # Now we see if we have any bonus budgets
            # These budgets come from tasks we decided not to run on
            # Each bonus target was added at a certain time.
            bonus_tasks = get_bonus_state()
            total_extra = 0

            print(f"🫥💴 Bonus tasks: {bonus_tasks}")

            for bonus_task in bonus_tasks[NUM_UNHARNESSED_TASKS:]:
                start_time = bonus_task.get("start_time", 0)
                excluded_tasks = []
                for task in self.get_seen_targets().values():
                    print(f"Comparing to {task}")
                    if task.get("start_time", 0) < start_time - 60*60:
                        excluded_tasks.append(task)

                num_tasks_left_to_process = total_num_tasks - len(excluded_tasks) - len(bonus_tasks)
                if num_tasks_left_to_process <= 0:
                    continue

                print(f"🫥 Extra budget from {bonus_task} split across {len(excluded_tasks)} tasks")

                bonus_budget = total_budget_for_task / num_tasks_left_to_process

                total_extra += bonus_budget


            if total_extra > 0:
                print(f"🫥💴 Total extra budget per task due to {len(bonus_tasks)} skipped tasks: {total_extra*100:.2f}%")

                total_budget_for_task += total_extra
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"🤡 Error calculating bonus budget: {e}")

                
        # We split its budget across all tasks which were started around the same time or after
        # So we calculate how many tasks are not included in this bonus
        # By checking the start time and seeing if any where started over an hour before the bonus target was added

        num_tasks_left_to_process = 0

        # Then we take the total number of included tasks and divide the bonus budget (which will be another amount of `total_budget_for_task` divided by the number of included tasks)

        rolling_period_minutes = self.get_rolling_period_minutes()

        active_projects = get_active_tasks()

        total_budget_for_active_tasks_in_this_period = 0

        print(f"🔢 Each task gets {total_budget_for_task*200:.2f}% for full and {total_budget_for_task*100:.2f}% for delta of the total budget overall")


        for task in active_projects:
            try:
                self.add_seen_target(task['task_id'], task)
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"🤡 Error adding seen target {task}: {e}")

            try:
                total_task_time_min = self.config["task_lengths"].get(task['type'], 8*60)
                if total_task_time_min == 0:
                    total_task_time_min = 1 # avoid crashes

                # For how many periods will this task be active
                num_periods_for_task = total_task_time_min / rolling_period_minutes

                if weighted_task_count > 0:
                    task_weight = 2 if task['type'] == 'full' else 1
                    total_budget_for_task = task_weight / weighted_task_count

                # This is how much of the total budget this task gets per period
                total_budget_for_task_per_period = total_budget_for_task / num_periods_for_task
                print(f"💹 Task: {task} getting additional {total_budget_for_task_per_period*100:.2f}% of the total budget this period")

                total_budget_for_active_tasks_in_this_period += total_budget_for_task_per_period
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"🤡 Error calculating budget for task {task}: {e}")

        return total_budget_for_active_tasks_in_this_period


    def roll_budget_for_budget(self, name, budget_percentage_per_period):
        budget = self.config["budgets"][name]

        max_budget = budget["max_budget"]

        per_period = budget_percentage_per_period * max_budget

        all_users_spend = self.state.get("users_spend", {})
        all_lost_user_spend = self.state.get("lost_user_spend", {})
        last_user_spend = all_users_spend.get(name, 0)
        lost_user_spend = all_lost_user_spend.get(name, 0)
        total_user_spend = last_user_spend + lost_user_spend

        budget_id = self.state["budget_ids"].get(name, None)
        if not budget_id:
            budget_id = create_new_budget(name, per_period)
            print(f"💸 Created new budget for {name} with id {budget_id} with ${per_period}")
            self.state["budget_ids"][name] = budget_id
            self.state["last_budget_amounts"][name] = per_period
            new_budget_amount = per_period
        else:
            # Add our per period to the budget
            last_budget_amount = self.state["last_budget_amounts"].get(name, 0)
            new_budget_amount = last_budget_amount + per_period

            if new_budget_amount > max_budget:
                new_budget_amount = max_budget

            to_set_budget_amt = new_budget_amount

            # Remove any spend that was lost due to reset
            if total_user_spend > max_budget + 5:
                print(f"🤡 {name} has spent ${last_user_spend:.2f} but the budget is only ${max_budget:.2f}, resetting the budget to 0.1")
                to_set_budget_amt = 0.1
                new_budget_amount = max_budget
                block_user(name)
            
            if lost_user_spend > 0:
                to_set_budget_amt -= lost_user_spend
            
            # Update the budget
            update_budget(budget_id, to_set_budget_amt)

            if to_set_budget_amt != new_budget_amount:
                print(f"💸 {name}: ${last_budget_amount:.2f} -> ${new_budget_amount:.2f} (actually limited to ${to_set_budget_amt:2f})")
            else:
                print(f"💸 {name}: ${last_budget_amount:.2f} -> ${new_budget_amount:.2f}")

            self.state["last_budget_amounts"][name] = new_budget_amount

        budget_id = sanity_check_budget(name, budget_id, new_budget_amount)
        if budget_id:
            self.state["budget_ids"][name] = budget_id
            self.state["last_budget_amounts"][name] = new_budget_amount
            save_state(self.state)
        
        user_info = get_user_info(name)
        if user_info:
            spend = user_info.get('spend', 0)
            print(f"💸 {name}: ${spend:.2f} / ${new_budget_amount:.2f}")
            if spend > max_budget:
                print(f"🤡 {name} has spent ${spend:.2f} but the budget is only ${max_budget:.2f}")
                block_user(name)


            if spend + 1 < last_user_spend:
                print(f"🤡 {name} has spent ${spend:.2f} but the last time they spent was ${last_user_spend:.2f}, SOMEHOW IT GOT RESET!!!!")
                # We assume the user's budget was reset, and the last user spend was already spent
                # So set that on
                lost_user_spend += last_user_spend - spend
                all_lost_user_spend[name] = lost_user_spend
                return

            all_users_spend[name] = spend

        self.state["users_spend"] = all_users_spend
        self.state["lost_user_spend"] = all_lost_user_spend
        save_state(self.state)

    def roll_budget(self):
        changed_state = False

        print("💹💹💹 UPDATING LITELLM BUDGETS 💹💹💹")

        # Calculate the budget percentage for this current period
        budget_percentage_per_period = self.calculate_budget_increases_percentage_of_total_budget()

        print(f"💹 For this period we are adding {budget_percentage_per_period*100:.2f}% of the total budget")

        # We are going to do this in the easiest way we can
        # At each roll period we add a fixed amount to each budget
        # This avoids needing to actually track usage as we can 
        # just keep upping the limit until we hit the max
        budgets = self.config["budgets"]
        for name in budgets.keys():
            try:
                self.roll_budget_for_budget(name, budget_percentage_per_period)
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"📉 Error rolling budget for {name}: {e}")


    def run(self):
        print("💰 Starting LLM Budget Manager 💰")
        period_seconds = self.get_rolling_period_seconds()

        self.init_budgets()

        next_roll_time = self.state.get("last_roll", 0) + period_seconds

        if time.time() > next_roll_time:
            next_roll_time = time.time()

        print(f"⏱️ Next budget roll time: {next_roll_time} vs {time.time()} (diff: {next_roll_time - time.time()})")

        while True:
            while time.time() < next_roll_time:
                time.sleep(5)

            roll_time = next_roll_time
            next_roll_time = roll_time + period_seconds

            self.roll_budget()

            self.state["last_roll"] = roll_time
            save_state(self.state)

            sys.stdout.flush()

            continue

    def init_budgets(self):
        # We check all budgets and if any of them are less than the INITIAL_BUDGET * MAX_FOR_BUDGET we set them to that value
        print("🚀 Initializing budgets...")

        budgets = self.config["budgets"]

        for name in budgets.keys():
            try:
                budget_config = budgets[name]
                max_budget = budget_config["max_budget"]

                # Calculate initial budget value - INITIAL_BUDGET is a multiplier of max_budget
                initial_budget_value = INITIAL_BUDGET * max_budget

                print(f"🔧 Checking budget for {name} (max: ${max_budget:.2f}, initial: ${initial_budget_value:.2f})")

                budget_id = self.state["budget_ids"].get(name, None)
                current_budget_amount = self.state["last_budget_amounts"].get(name, 0)

                if not budget_id:
                    # Budget doesn't exist, create it
                    print(f"📝 Creating new budget for {name}")
                    budget_id = create_new_budget(name, initial_budget_value)
                    self.state["budget_ids"][name] = budget_id
                    self.state["last_budget_amounts"][name] = initial_budget_value
                    print(f"✅ Created budget {budget_id} for {name} with ${initial_budget_value:.2f}")
                else:
                    # Budget exists, check if it needs to be increased to initial value
                    if current_budget_amount < initial_budget_value:
                        print(f"📈 Increasing budget for {name} from ${current_budget_amount:.2f} to ${initial_budget_value:.2f}")
                        update_budget(budget_id, initial_budget_value)
                        self.state["last_budget_amounts"][name] = initial_budget_value
                        print(f"✅ Updated budget for {name} to ${initial_budget_value:.2f}")
                    else:
                        print(f"✅ Budget for {name} already at ${current_budget_amount:.2f} (>= ${initial_budget_value:.2f})")

                # Ensure budget is properly configured
                budget_id = sanity_check_budget(name, budget_id, self.state["last_budget_amounts"][name])
                if budget_id:
                    self.state["budget_ids"][name] = budget_id

            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"❌ Error initializing budget for {name}: {e}")

        # Save state after initialization
        save_state(self.state)
        print("🎉 Budget initialization complete!")
        sys.stdout.flush()


def main():
    config = get_config()
    state = get_state()

    print(f"💰 Starting LLM Budget Manager with config: {config}")
    print(f"💰 Starting LLM Budget Manager with state: {state}")
    sys.stdout.flush()

    wait_until_litellm_running()

    budget_manager = BudgetManager(config, state)

    budget_manager.run()


if __name__ == "__main__":
    main()
