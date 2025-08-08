#!/usr/bin/env python3
import yaml
import plotly.figure_factory as ff
import os
from datetime import datetime
import sys
from dataclasses import dataclass, asdict
# from tabulate import tabulate

@dataclass
class TaskInfo:
    name: str
    start_time: datetime
    end_time: datetime
    success: bool
    timeout: bool

    def duration(self):
        """Calculates the duration and returns it in a formatted string (e.g., '3m 3s')."""
        delta = self.end_time - self.start_time
        minutes, seconds = divmod(delta.total_seconds(), 60)
        return f"{int(minutes)}m {int(seconds)}s"

def find_target_files(base_directory):
    """Finds and returns a list of target YAML file paths in directories ending with '.done'."""
    target_files = []
    for task_dir in os.listdir(base_directory):
        dir_path = os.path.join(base_directory, task_dir)
        if os.path.isdir(dir_path) and task_dir.endswith('.done'):
            for filename in os.listdir(dir_path):
                if filename.endswith('.yaml'):
                    file_path = os.path.join(dir_path, filename)
                    target_files.append((task_dir[:-5], file_path))  # Exclude '.done' and store task name
    return target_files

def parse_files(task_files):
    """Parses the YAML files, supports two formats and extracts data accordingly, using dataclasses."""
    task_data = []
    for task_name, file_path in task_files:
        with open(file_path, 'r') as file:
            data = yaml.safe_load(file)
        
        if 'replicas_done' in data:
            for replica_id, replica_data in data['replicas_done'].items():
                task_data.append(parse_replica(task_name, replica_id, replica_data))
        else:
            task_data.append(parse_task(task_name, data))
    return task_data

def parse_replica(task_name, replica_id, data):
    start_time = convert_to_datetime(data['start_time'])
    end_time = convert_to_datetime(data['end_time'])
    full_task_name = f"{task_name}_{replica_id}"
    return TaskInfo(full_task_name, start_time, end_time, data['success'], data['timeout'])

def parse_task(task_name, data):
    start_time = convert_to_datetime(data['start_time'])
    end_time = convert_to_datetime(data['end_time'])
    return TaskInfo(task_name, start_time, end_time, data['success'], data['timeout'])

def convert_to_datetime(date_str):
    """Safely converts a string to a datetime object, handling non-string types."""
    if isinstance(date_str, datetime):
        return date_str
    try:
        return datetime.fromisoformat(date_str)
    except TypeError:
        raise ValueError(f"Expected ISO format datetime string, got {type(date_str)}: {date_str}")

def plot_task_durations(task_data):
    """Plots task durations on a Gantt chart using Plotly, color-coded by success, and saves it as an HTML file."""
    df = []
    for task in task_data:
        color = 'green' if task.success else 'red'  # Set color based on success
        df.append(dict(Task=f"{task.name} ({task.duration()})", Start=task.start_time, Finish=task.end_time, Color=color))

    # Define color mapping
    colors = {'red': 'rgb(255, 0, 0)', 'green': 'rgb(0, 255, 0)'}
    fig = ff.create_gantt(df, colors=colors, index_col='Color', show_colorbar=True, group_tasks=True, title='Task Durations')

    # Save the figure as HTML
    fig.write_html('/tmp/task_durations.html')
    print("Plot saved to '/tmp/task_durations.html'")

# def display_task_data(task_data):
#     """Displays task data in a tabular format using tabulate."""
#     table_data = [[task.name, task.start_time, task.end_time, task.duration(), task.success, task.timeout, task.exit_code] for task in task_data]
#     headers = ["Task Name", "Start Time", "End Time", "Duration", "Success", "Timeout", "Exit Code"]
#     print(tabulate(table_data, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <path_to_base_directory>")
        sys.exit(1)

    base_directory = sys.argv[1]
    task_files = find_target_files(base_directory)
    task_data = parse_files(task_files)
    plot_task_durations(task_data)
    # display_task_data(task_data)  