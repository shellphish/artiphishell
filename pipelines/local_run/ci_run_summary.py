#!/usr/bin/env python3
import argparse
from dataclasses import dataclass, field
import json
import pathlib
import tempfile
from typing import Any, Dict, List, Optional
import requests
import re
import os
from discord import SyncWebhook
import aiohttp
from tabulate import tabulate

# from icecream import ic

OWNER = "shellphish-support-syndicate"
REPO = "pipelines"
THIS_DIR = pathlib.Path(__file__).parent

@dataclass
class Component:
    name: str
    iskernel: bool
    isjenkins: bool
    isgeneric: bool
    run : List['ComponentRun'] = field(default_factory=list)
    
    def add_run(self, run: 'ComponentRun'):
        self.run.append(run)

@dataclass
class ComponentRun:
    component : Component
    status: str
    log_links: "LogEntry"
    target: "Target"

    @property
    def ran(self):
        return self.status != NO_RUN

@dataclass
class LogEntry:
    status: str
    link: str

@dataclass
class Target:
    name: str
    url: str
    iskernel: bool = field(init=False, default=False)
    isjenkins: bool = field(init=False, default=False)
    isgeneric: bool = field(init=False, default=False)
    
    vds: int = field(init=False, default=0)
    gp: int = field(init=False, default=0)
    
    def __post_init__(self):
        if "jenkins" in self.name:
            self.isjenkins = True
        elif "linux" in self.name:
            self.iskernel = True
        else:
            self.isgeneric = True
            
SUCCESS_STATUS = 'ğŸŸ©'            
RUNNING_STATUS = 'ğŸ�ƒ'
FAILED_STATUS = 'ğŸŸ¥'
NO_RUN_STATUS = 'â¬œ'

SUCCESS = "SUCCESS"
RUNNING = "RUNNING"
FAILED = "FAILED"
NO_RUN = "NO_RUN"

def should_have_run(component : Component, target : Target):
    if component.isjenkins and target.isjenkins:
        return True
    if component.iskernel and target.iskernel:
        return True
    if component.isgeneric and target.isgeneric:
        return True
    return False

def get_status(status: str) -> str:
    status = status.strip()
    if status == SUCCESS_STATUS or SUCCESS_STATUS in status or "🟩" in status:
        return SUCCESS
    elif status == RUNNING_STATUS or RUNNING_STATUS in status or "🏃" in status:
        return RUNNING
    elif status == FAILED_STATUS or FAILED_STATUS in status or "🟥" in status: 
        return FAILED
    elif status == NO_RUN_STATUS or NO_RUN_STATUS in status or "⬜" in status:
        return NO_RUN
    else:
        raise Exception(f"Unknown status: {status}")

def get_summaries(run_id: int, targets : List[str], directory) -> List[Target]:
    target_objs = []
    for target_name in targets:
        url = f"https://aixcc-diskman.adamdoupe.com/iKbr6hfymftxL7pr3FEX/pipeline-backup/{target_name}/{run_id}/summary.md" 
        response = requests.get(url)
        if response.status_code == 200:
            with open(directory / f"{target_name}_summary.md", "w") as f:
                f.write(response.text)
            print(f"Downloaded {target_name} summary to {directory / f'{target_name}_summary.md'}")
            target_objs.append(Target(name=target_name, url=url))
        else:
            print(f"Error: accessing {url} with {response.status_code}")     
    return target_objs

class ComponentRegistry:
    def __init__(self, json_filepath: str):
        self.json_filepath = json_filepath
        self.runs = []
        
        self.components: Dict[str, Component] = {}
        self.target_runs: Dict[str, List[ComponentRun]] = {}
        self.targets = {}
        self.load_components_from_json(json_filepath)

    def add_summary(self, target_obj : Target, markdown_filepath: str):
        self.target_runs[target_obj.name] = []
        self.targets[target_obj.name] = target_obj
        self.load_component_runs_from_md(target_obj, markdown_filepath)

    def load_components_from_json(self, filepath: str):
        with open(filepath, 'rb') as file:
            data = json.load(file)
            for item in data['components']:
                component = Component(
                    name=item['name'],
                    iskernel=item.get('kernel', False),
                    isjenkins=item.get('jenkins', False),
                    isgeneric=item.get('generic-c', False)
                )
                self.components[component.name] = component

    def load_component_runs_from_md(self, target : Target, filepath: str):
        with open(filepath, 'r') as file:
            lines = file.readlines()
            for line in lines:
                self.parse_submissions(line, target)
                component_runs = self.parse_component_run_line(line, target)
                self.target_runs[target.name].extend(component_runs)

    def parse_submissions(self, line : str, target : Target):
        # | VDS | 0 | 0 | 0 | N/A | 
        pattern = r"\|\s*(.+?)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\S+)\s*\|"
        match = re.search(pattern, line)
        if match:
            name, total, success, pending, success_rate = match.groups()
            if name == "VDS":
                target.vds = int(total)
            elif name == "GP":
                target.gp = int(total)
        
    def parse_component_run_line(self, line: str, target : Target) -> Optional[ComponentRun]:
        pattern = r"\|\s*(.+?)\s*\|\s*(\S+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\S+)\s*\|\s*(.+?)\s*\|"
        match = re.search(pattern, line)
        cruns = []
        if match:
            name, status, num_ran, num_running, num_success, success_rate, log_links = match.groups()
            num_ran, num_running, num_success = map(int, [num_ran, num_running, num_success])
            try:
                component = self.get_component(name)
                links = self.parse_log_links(log_links)
                for link in links:
                    crun = ComponentRun(component, link.status, link, target)
                    component.add_run(crun)
                    cruns.append(crun)
                if len(links) == 0:
                    crun = ComponentRun(component, NO_RUN, None, target)
                    component.add_run(crun)
                    cruns.append(crun)
                return cruns
            except Exception:
                print(f"Missing a component with {name}")
        return cruns
    
    def parse_log_links(self, input_string: str) -> List[str]:
        pattern = re.compile(r'\[(.+?)\]\((.+?)\)')
        matches = pattern.findall(input_string)
        return [LogEntry(status=get_status(status), link=link) for status, link in matches]

    def get_component(self, name: str):
        return self.components[name]
    
    def get_all_components(self):
        return list(self.components.values())

    def get_target_runs(self, name: str):
        return self.target_runs.get(name)

    def get_targets_run(self):
        return list(self.target_runs.keys())

    def get_components_run_during_run(self):
        # set of components that ran during the run
        components = set()
        for target in self.get_targets_run():
            for run in self.get_component_runs(target):
                components.add(run.component.name)
        return [self.get_component(name) for name in components]
       
    def get_component_runs(self, name: str):
        component = self.get_component(name)
        return component.run
        
    def filter_component_runs(self, name: str, status: Optional[str] = None, target = None):
        runs = self.get_component_runs(name)
        if status is not None:
            runs = [run for run in runs if run.status == status and run.target.name == target]
        else: 
            runs = [run for run in runs if run.target.name == target and run.status != NO_RUN]
        return runs

    def get_components_run_info(self, target_name: str):
        runs = self.get_target_runs(target_name)
        did_not_run = []
        should_not_run = []
        ran = []
        
        for component_instance in runs:
            if component_instance.ran:
                ran.append(component_instance)
            if should_have_run(component_instance.component, self.targets[target_name]):
                if not component_instance.ran:
                    did_not_run.append(component_instance)
            else:
                if component_instance.ran:
                    should_not_run.append(component_instance)
       
        return {
            "ran": [inst.component.name for inst in ran],
            "did_not_run": [inst.component.name for inst in did_not_run],
            "should_not_run": [inst.component.name for inst in should_not_run]
        } 

    def per_component_stats(self):
        components = self.get_all_components()
        stats = {}
        for component in components:
            failed_runs = []
            killed_runs = []
            success_runs = []
            did_not_run = []
            no_run_when_not_needed = []
            unecessary_runs = []
            for target in self.get_targets_run():
                if should_have_run(component, self.targets[target]):
                    failed_runs.extend(self.filter_component_runs(component.name, status=FAILED, target=target))
                    killed_runs.extend(self.filter_component_runs(component.name, status=RUNNING, target=target))
                    success_runs.extend(self.filter_component_runs(component.name, status=SUCCESS, target=target))
                    did_not_run.extend(self.filter_component_runs(component.name, status=NO_RUN, target=target))
                else:
                    unecessary_runs.extend(self.filter_component_runs(component.name, target=target))
                    no_run_when_not_needed.extend(self.filter_component_runs(component.name, status=NO_RUN, target=target))
            total_runs = len(failed_runs) + len(killed_runs) + len(success_runs) + len(did_not_run) + len(unecessary_runs)
            # assert total_runs > 0 or len(no_run_when_not_needed) > 0, f"Error: {component.name} has not runs in the markdown file at all. {component.run}"
            if total_runs > 0:
                stats[component.name] = { 
                    "fail-rate" : len(failed_runs) / total_runs * 100,
                    "success-rate" : (len(success_runs) + len(killed_runs)) / total_runs * 100,
                    "did-not-run" : len(did_not_run), 
                    "unecessary-run-cnt" : len(unecessary_runs),
                    "total-runs" : total_runs,
                    "unecessary-runs" : unecessary_runs,
                    "failed-runs" : failed_runs,
                }
        return stats
    
    def were_all_needed_components_run(self, target_name: str):
        for component in self.get_all_components():
            if should_have_run(component, self.targets[target_name]):
                runs = self.filter_component_runs(component.name, target=target_name)
                if len(runs) == 0:
                    return False
        return True
        
    def target_detailed_runs(self):
        stats = {}
        for target in self.get_targets_run():
            stats[target] = {
                "vds submitted" : self.targets[target].vds,
                "gp submitted" : self.targets[target].gp,
                "all_needed_components_ran" : self.were_all_needed_components_run(target),
            }
        return stats
    
    def all_targets_stats(self):
        stats = {}
        target_stats = self.target_detailed_runs()
        vds_submitted = 0
        gp_submitted = 0
        targets_with_vd_submitted = 0
        targets_with_gp_submitted = 0
        for target in self.get_targets_run(): 
            if target_stats[target]["vds submitted"] > 0:
                vds_submitted += target_stats[target]["vds submitted"]
                targets_with_vd_submitted += 1
            if target_stats[target]["gp submitted"] > 0:
                gp_submitted += target_stats[target]["gp submitted"]
                targets_with_gp_submitted += 1
        stats["vds_submitted"] = vds_submitted
        stats["gp_submitted"] = gp_submitted
        stats["targets_with_vd_submitted"] = targets_with_vd_submitted
        stats["targets_with_gp_submitted"] = targets_with_gp_submitted
        return stats

def main(directory : pathlib.Path):
    parser = argparse.ArgumentParser(description='Get GitHub Actions job information.')
    parser.add_argument('--run-id', type=int, required=True, help='The GitHub Actions run ID')
    # parser.add_argument('--output', type=str, default="summary.md", help='The output file to write the summary to.')
    parser.add_argument('--targets', type=str, default="targets.json", help='The targets to get the summaries for.')
    parser.add_argument('--markdown', type=bool, default=False, help='Whether to output markdown or not.')
    args = parser.parse_args()

    run_id = args.run_id
    targets_json = json.load(open(args.targets))
    targets = []
    for target in targets_json:
        targets.append(target['short-name'])

    registry = ComponentRegistry(THIS_DIR / "components.json")
    target_objs = get_summaries(run_id=run_id, targets=targets, directory=directory)

    # go through summaries in the directory
    for target in target_objs:
        summary_file = directory / f"{target.name}_summary.md"
        registry.add_summary(target, summary_file)

        # get the components that ran during the run
        # info = registry.get_components_run_info(target)    
        
    if args.markdown:
        header = generate_markdown_header("Pipeline Run Summary", target_objs)
        total_stats = registry.all_targets_stats()
        total_stats_table = convert_total_stats_to_markdown(total_stats)
        per_target_stats = registry.target_detailed_runs()
        per_target_stats_table = convert_target_stats_to_markdown(per_target_stats)
        stats = registry.per_component_stats()
        stats_table = convert_stats_to_markdown(stats)
        output = total_stats_table + "\n\n" + per_target_stats_table + "\n\n" + stats_table
        print(output)
    else:
        if len(target_objs) == 0:
            print("Error: No targets found.")
            os.system(f"rm -rf {directory}")
            exit(1)
        #print(header + total_stats_ascii)
        header = generate_discord_message_header("Pipeline Run Summary", target_objs)
        total_stats = registry.all_targets_stats()
        total_stats_ascii = convert_total_stats_to_ascii(total_stats)
        print(total_stats_ascii)
        send(header) 
        send_table(total_stats_ascii)
        
        header = generate_discord_message_header("Submissions Per Target", target_objs)
        per_target_stats = registry.target_detailed_runs()
        per_target_stats_ascii = convert_target_stats_to_ascii(per_target_stats)
        print(per_target_stats_ascii)
        send(header)
        send_table(per_target_stats_ascii)

        stats = registry.per_component_stats()
        header = generate_discord_message_header("Component Stats", target_objs)
        stats_ascii = convert_stats_to_message(stats)
        print(stats_ascii)
        send(header + "\n" + stats_ascii)
        # send_table(stats_ascii)
        
    os.system(f"rm -rf {directory}")

#
# Markdown crap
# 

def generate_discord_message_header(title: str, target_objs: List[Target]) -> str:
    URL = f"https://github.com/shellphish-support-syndicate/pipelines/actions/runs/{RUN_ID}"
    header = f"**{title}** - [Workflow run - {RUN_ID}]({URL})\n"
    header += "The following Targets ran during this pipeline run: "
    for target in target_objs:
        header += f"[{target.name}]({target.url}), "
    header += "\n"
    return header


def convert_total_stats_to_ascii(data) -> str:
    table = [
        ["Total VDS Submitted", "Total GP Submitted", "Targets with VDS Submitted", "Targets with GP Submitted"],
        [data['vds_submitted'], data['gp_submitted'], data['targets_with_vd_submitted'], data['targets_with_gp_submitted']]
    ]
    return tabulate(table, headers="firstrow", tablefmt="simple_grid")

def convert_target_stats_to_ascii(data) -> str:
    table = [
        ["Target", "VDS Submitted", "GP Submitted", "All Needed Components Ran"]
    ]
    for target, metrics in data.items():
        table.append([
            target,
            metrics['vds submitted'],
            metrics['gp submitted'],
            metrics['all_needed_components_ran']
        ])
    return tabulate(table, headers="firstrow", tablefmt="simple_grid")

def convert_stats_to_ascii(data) -> str:
    table = [
        ["Component", "Fail Rate (%)", "Success Rate (%)", "Did Not Run", "Unecessary Runs", "Total Runs"]
    ]

    for target, metrics in data.items():
        failed_run_string = " ".join([f"[{run.target.name}]({run.log_links.link})" for run in metrics['failed-runs']])
        unecessary_run_string = " ".join([f"[{run.target.name}]({run.log_links.link})" for run in metrics['unecessary-runs']])
        
        row = [
            target,
            f"{metrics['fail-rate']} {failed_run_string}",
            metrics['success-rate'],
            metrics['did-not-run'],
            f"{metrics['unecessary-run-cnt']} {unecessary_run_string}",
            metrics['total-runs']
        ]
        table.append(row)
    
    return tabulate(table, headers="firstrow", tablefmt="simple_grid")

def generate_markdown_header(title: str, target_objs: List[Target]) -> str:
    header = f"# {title}\n\n"
    header += "## Summary\n\n"
    header += "The following Targets ran during this pipeline run:\n\n"
    for target in target_objs:
        header += f"- [{target.name}]({target.url})\n"
    header += "\n"
    return header

def convert_total_stats_to_markdown(data) -> str:
    header = "## Total Stats\n"
    header += "| Total VDS Submitted | Total GP Submitted | Targets with VDS Submitted | Targets with GP Submitted |"
    separator = "|----------------------|---------------------|---------------------------|--------------------------|"
    row = f"| {data['vds_submitted']} | {data['gp_submitted']} | {data['targets_with_vd_submitted']} | {data['targets_with_gp_submitted']} |"
    return "\n".join([header, separator, row])

def convert_target_stats_to_markdown(data) -> str:
    header = "## Target Stats\n"
    header += "| Target | VDS Submitted | GP Submitted | All Needed Components Ran |"
    separator = "|--------|---------------|--------------|--------------------------|"
    table = [header, separator]
    for target, metrics in data.items():
        row = f"| {target} | {metrics['vds submitted']} | {metrics['gp submitted']} | {metrics['all_needed_components_ran']} |"
        table.append(row)
    return "\n".join(table)

def convert_stats_to_message(data) -> str:
    output = "🤡 **Components that failed during the run :\n**" 
    for component, metrics in data.items():
        if metrics['fail-rate'] > 0:
            failed_links = ""
            for run in metrics['failed-runs']:
                failed_links += f"[{run.target.name}]({run.log_links.link}) "
            output += f"{component} : {metrics['fail-rate']}% failure rate | Failed on : {failed_links}\n"
    output += "\n"
    output += "🤡 **Components that shouldn't have run :\n**"
    for component, metrics in data.items():
        if metrics['unecessary-run-cnt'] > 0:
            unecessary_links = ""
            for run in metrics['unecessary-runs']:
                unecessary_links += f"[{run.target.name}]({run.log_links.link}) "
            output += f"{component} : {metrics['unecessary-run-cnt']} times | Ran on : {unecessary_links}\n"
    return output


def convert_stats_to_markdown(data) -> str:
    header = "## Component Stats\n"
    # Define the table header
    header += "| Component |  Fail Rate (%) | Success Rate (%) | Did Not Run |  Unecessary Runs | Total Runs |" 
    separator = "|--------|----------------|---------------|------------------|------------------|------------|"

    # Initialize the table with the header and separator
    table = [header, separator]

    
    # Populate the table rows
    for target, metrics in data.items():
        failed_run_string = ""
        for run in metrics['failed-runs']:
            failed_run_string += f"[{run.target.name}]({run.log_links.link}) "
        
        unecessary_run_string = ""
        for run in metrics['unecessary-runs']:
            unecessary_run_string += f"[{run.target.name}]({run.log_links.link}) "
       
        row = f"| {target} |  {metrics['fail-rate']} {failed_run_string} | {metrics['success-rate']}  | {metrics['did-not-run']} | {metrics['unecessary-run-cnt']} {unecessary_run_string} | {metrics['total-runs']} |"
        table.append(row)

    # Join the table list into a single string with newline characters
    return "\n".join(table)

def send_table(message):
    if len(message) <= 2000:
        webhook.send("```" + message + "```")
    else:
        start = 0
        while start < len(message):
            end = start + 2000
            if end >= len(message):
                webhook.send(message[start:])
                break
            newline_pos = message.rfind('\n', start, end)
            if newline_pos == -1:
                newline_pos = end
            webhook.send("```" + message[start:newline_pos] + "```")
            start = newline_pos + 1

def send(message):
    if len(message) <= 2000:
        webhook.send(message)
    else:
        start = 0
        while start < len(message):
            end = start + 2000
            if end >= len(message):
                webhook.send(message[start:])
                break
            newline_pos = message.rfind('\n', start, end)
            if newline_pos == -1:
                newline_pos = end
            webhook.send(message[start:newline_pos])
            start = newline_pos + 1

if __name__ == '__main__':
    WEBHOOK_URL = os.getenv('WEBHOOK')
    if not WEBHOOK_URL:
        print("Error: WEBHOOK environment variable is not set.")
        exit(1)
        
    RUN_ID = os.getenv('RUN_ID')
    if not RUN_ID:
        print("Error: RUN_ID environment variable is not set.")
        exit(1)
    
    webhook = SyncWebhook.from_url(WEBHOOK_URL)
    # create a temp directory to store the summaries
    tempdir = pathlib.Path(tempfile.mkdtemp())
    main(tempdir)
