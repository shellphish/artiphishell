#!/usr/bin/env python3
import docker
import pandas as pd
import plotly.express as px
import time
import os
import psutil
import argparse
import tempfile
import shutil
import glob
import json
import re

# Initialize Docker client
client = docker.from_env()

# Dataframes to store container stats and labels
stats_columns = ['Name', 'CPU%', 'MEM%', 'Timestamp']
stats_data = pd.DataFrame(columns=stats_columns)
labels_columns = ['Name', 'Labels']
labels_data = pd.DataFrame(columns=labels_columns)

# Define the maximum runtime in seconds and dump interval
MAX_RUNTIME = 15600  # 4 hours and 20 minutes in seconds
DUMP_INTERVAL = 600  # Dump every 10 minutes
STOP_SIGNAL_FILE = '/tmp/STOP_THE_PYTHON_LOGGER'
TEMP_DIR = tempfile.mkdtemp()

LOG_FILE = '/tmp/docker_mon.log'

def log(message):
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(f"{pd.Timestamp.now()} | {message}\n")

def parse_args():
    parser = argparse.ArgumentParser(description="Monitor Docker containers and system stats")
    parser.add_argument('--dump', type=str, help='Dump the dataframes to specified file path')
    parser.add_argument('--load', type=str, help='Load the dataframes from specified file path')
    parser.add_argument('--plot', action='store_true', help='Generate plots from data and store in /tmp')
    return parser.parse_args()

def stop_signal_detected():
    if os.path.exists(STOP_SIGNAL_FILE):
        log("Stop signal detected, stopping data collection.")
        os.remove(STOP_SIGNAL_FILE)
        return True
    return False

def collect_data():
    global stats_data
    
    start_time = time.time()
    last_dump_time = start_time
    log(f"Starting data collection....")

    while not stop_signal_detected():
        if (time.time() - start_time) > MAX_RUNTIME:
            print("Maximum runtime exceeded, stopping data collection.")
            break

        if (time.time() - last_dump_time) >= DUMP_INTERVAL:
            dump_data_to_temp(stats_data)
            stats_data = stats_data.iloc[0:0]  # Clear dataframe after dumping
            last_dump_time = time.time()

        # Collect total system stats
        total_cpu_percent = psutil.cpu_percent(interval=None)
        total_mem = psutil.virtual_memory()
        total_mem_percent = total_mem.percent
        
        stats_data.loc[len(stats_data)] = [
            'TOTAL_STATS',
            total_cpu_percent,
            total_mem_percent,
            pd.Timestamp.now()
        ]

        try:
            current_containers = client.containers.list()
            update_stats_data(stats_data, current_containers)
        except KeyError:
            log("KeyError occurred, skipping current iteration.")
        except docker.errors.NotFound:
            log("Container not found, skipping current iteration.")
        except Exception as e:
            log(f"An error occurred: {e}")

    log("Data collection interrupted, stopping.")
    dump_data_to_temp(stats_data) # Dump any remaining data
    stats_data = stats_data.iloc[0:0]  # Clear dataframe after dumping

def update_stats_data(stats_data, containers):
    for container in containers:
        if container.name.startswith("aixcc"):
            continue
        stats = container.stats(stream=False)
        cpu_percent = calculate_cpu_percent(stats)
        mem_usage = stats['memory_stats']['usage']
        mem_limit = stats['memory_stats']['limit']
        mem_percent = (mem_usage / mem_limit) * 100

        # Record labels directly without modification
        if container.name not in labels_data['Name'].values:
            labels_data.loc[len(labels_data)] = [container.name, json.dumps(container.labels)]

        stats_data.loc[len(stats_data)] = [container.name, cpu_percent, mem_percent, pd.Timestamp.now()]

def calculate_cpu_percent(stats):
    cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
    system_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
    if system_delta > 0 and cpu_delta > 0:
        # return (cpu_delta / system_delta) * stats['cpu_stats']['online_cpus'] * 100.0
        return (cpu_delta / system_delta) * 100.0
    return 0

def dump_data_to_temp(df):
    temp_file = os.path.join(TEMP_DIR, f"temp_data_{int(time.time())}.csv")
    df.to_csv(temp_file, index=False)

def aggregate_temp_data(stats_data):
    all_files = glob.glob(os.path.join(TEMP_DIR, "temp_data_*.csv"))
    df_list = [pd.read_csv(file, parse_dates=['Timestamp']) for file in all_files]
    full_data = None
    if df_list != []:
        df_list.append(stats_data)
        full_data = pd.concat(df_list, ignore_index=True)
    else:
        full_data = stats_data 
    shutil.rmtree(TEMP_DIR)  # Clean up the temp directory after aggregating data
    return full_data

# Assuming TASK, SUB_TASK, IGNORE are predefined as:
TASK, SUB_TASK, IGNORE = 0, 1, 2

def process_names(name, labels):
    crs = re.compile(r"^CRS___(.*?)___(.*?)___(.*?)$")
    match = crs.match(name)
    if match:
        return match.group(1) + "_" + match.group(2) + "_" + match.group(3), name, TASK
    else:
        crs2 = re.compile(r"^CRS-set___(.*?)___(.*?)___(.*?)$")
        match2 = crs2.match(name)
        if match2:
            return match2.group(1) + "_" + match2.group(2) + "_" + match2.group(3), name, TASK
        else:
            if name.startswith("aixcc"):
                return name, name, IGNORE
            else:
                if "owner_task" not in labels:
                    return name, name, IGNORE
                else:
                    return name, name, SUB_TASK

def get_owner_task(labels):
    if 'owner_task' in labels:
        return labels['owner_task'] + "_" + labels['owner_job'] + "_" + labels['owner_replica']
    else:
        print(f"Owner task not found in labels: {labels}")

def process_labels_for_tasks(labels_data):
    task_mapping = {}
    name_full_name_mapping = {}
    for index, row in labels_data.iterrows():
        labels = json.loads(row['Labels'])
        name, full_name, task_type = process_names(row['Name'], labels)
        if task_type == IGNORE:
            continue
        elif task_type == TASK:
            if name not in task_mapping:
                task_mapping[name] = []
            if name not in name_full_name_mapping:
                name_full_name_mapping[name] = full_name
        elif task_type == SUB_TASK:
            owner_task = get_owner_task(labels)
            if owner_task:
                if owner_task not in task_mapping:
                    task_mapping[owner_task] = []
                task_mapping[owner_task].append(name)
    return task_mapping, name_full_name_mapping

def generate_plots(stats_data, labels_data):
    plot_dir = '/tmp/container_plots'
    if not os.path.exists(plot_dir):
        os.makedirs(plot_dir)
    task_mapping, name_mapping = process_labels_for_tasks(labels_data)
    color_list = ['red', 'green', 'orange', 'purple', 'brown', 'pink', 'black']  # Add more colors as needed
    total_stats_data = stats_data[stats_data['Name'] == 'TOTAL_STATS']

    for task, sub_tasks in task_mapping.items():
        try:
            actual_name = name_mapping[task]
            relevant_names = [actual_name] + sub_tasks
            group_df = stats_data[stats_data['Name'].isin(relevant_names)]
            if not group_df.empty:
                # Determine the time range for the current task and subtasks
                group_df = group_df.sort_values(by='Timestamp')
                min_timestamp = group_df['Timestamp'].min()
                max_timestamp = group_df['Timestamp'].max()

                # Filter the total_stats data to match the time range of the current task
                relevant_total_stats = total_stats_data[(total_stats_data['Timestamp'] >= min_timestamp) &
                                                        (total_stats_data['Timestamp'] <= max_timestamp)]
                relevant_total_stats = relevant_total_stats.sort_values(by='Timestamp')

                # Create the initial plot for the main task in blue
                fig = px.line(group_df[group_df['Name'] == actual_name], x='Timestamp', y='CPU%', color_discrete_sequence=['blue'],
                            labels={'value': 'CPU Usage (%)', 'variable': 'Resource'}, title=f'CPU and MEM Usage for {task}')
                fig.add_scatter(x=group_df[group_df['Name'] == actual_name]['Timestamp'], y=group_df[group_df['Name'] == actual_name]['MEM%'],
                                mode='lines+markers', name='MEM Usage (%)', line=dict(color='blue'))

                # Add sub-tasks in different colors
                sub_color_idx = 0
                for sub_task in sub_tasks:
                    sub_task_data = group_df[group_df['Name'] == sub_task]
                    color = color_list[sub_color_idx % len(color_list)]
                    color2 = color_list[(sub_color_idx + 1) % len(color_list)]
                    fig.add_scatter(x=sub_task_data['Timestamp'], y=sub_task_data['CPU%'], mode='lines+markers',
                                    name=f'{sub_task} CPU', line=dict(color=color))
                    fig.add_scatter(x=sub_task_data['Timestamp'], y=sub_task_data['MEM%'], mode='lines+markers',
                                    name=f'{sub_task} MEM', line=dict(color=color2))
                    sub_color_idx += 2
                    
                fig.add_scatter(x=relevant_total_stats['Timestamp'], y=relevant_total_stats['CPU%'], mode='lines+markers',
                                name='Total CPU', line=dict(color='black', dash='dash'))
                fig.add_scatter(x=relevant_total_stats['Timestamp'], y=relevant_total_stats['MEM%'], mode='lines+markers',
                                name='Total MEM', line=dict(color='black', dash='dash'))

                log(f"Generating plot for {task} at {plot_dir}/{task}_usage.html...")
                fig.update_layout(legend_title_text='Resource')
                fig.write_html(f'{plot_dir}/{task}_usage.html')
        except Exception as e:
            log(f"An error occurred while generating plots: {e}")

def generate_index_html(plot_dir):
    html_content = "<html><head><title>Usage Plots Index</title></head><body>"
    html_content += "<h1>Index of Usage Plots</h1><ul>"
    
    # List all HTML files in the plot directory
    for filename in os.listdir(plot_dir):
        if filename.endswith(".html"):
            html_content += f'<li><a href="{filename}">{filename}</a></li>'
    
    html_content += "</ul></body></html>"
    
    # Write the index.html file
    with open(os.path.join(plot_dir, 'index.html'), 'w') as file:
        file.write(html_content)

def dump_data(filepath, agg_stats_data):
    agg_stats_data.to_csv(filepath + '_stats.csv', index=False)
    labels_data.to_csv(filepath + '_labels.csv', index=False)

def load_data(filepath):
    global stats_data, labels_data
    stats_data = pd.read_csv(filepath + '_stats.csv')
    labels_data = pd.read_csv(filepath + '_labels.csv')

if __name__ == '__main__':
    agg_stats_data = None
    os.system(f"rm {LOG_FILE}")
    os.system(f"touch {LOG_FILE}")
    os.system(f"rm {STOP_SIGNAL_FILE}")
    args = parse_args()
    if args.load:
        load_data(args.load)
        agg_stats_data = stats_data
    else:
        log("Starting data collection...")
        try:
            collect_data()
        except KeyboardInterrupt:
            print("Data collection interrupted by keyboard interrupt, stopping.")
        log("Data collection completed... Aggregating data.")
        agg_stats_data = aggregate_temp_data(stats_data)
        log("Data aggregation completed.")
    if args.dump:
        log("Dumping aggregated data to specified file.")
        dump_data(args.dump, agg_stats_data)
    if args.plot:
        log("Generating plots from aggregated data.")
        try:
            generate_plots(agg_stats_data, labels_data)
        except Exception as e:
            log(f"Plotting failed with {e}")
        generate_index_html('/tmp/container_plots')
        log("Plots should be ready and stored")
