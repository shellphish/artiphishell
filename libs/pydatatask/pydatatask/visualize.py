"""Visualizes the pipeline live using dash to plot the graph and update the status of each node over time."""

from typing import Any, List
import asyncio
import json
import threading
import time

from dash import dcc, html
from dash.dependencies import Input, Output
from janus import Queue
import dash
import networkx as nx
import plotly.graph_objects as go
import yaml
import os
from .repository import (
    BlobRepository,
    MetadataRepository,
)

_default_index = """<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
            :root {
                --primary-color: #2c3e50;
                --secondary-color: #34495e;
                --accent-color: #3498db;
                --success-color: #2ecc71;
                --warning-color: #f1c40f;
                --error-color: #e74c3c;
                --text-color: #2c3e50;
                --bg-color: #f8f9fa;
                --card-bg: #ffffff;
                --fish-color: invert(42%) sepia(93%) saturate(1352%) hue-rotate(87deg) brightness(119%) contrast(119%);

            }

            [data-theme="dark"] {
                --primary-color: #ecf0f1;
                --secondary-color: #bdc3c7;
                --accent-color: #3498db;
                --success-color: #2ecc71;
                --warning-color: #f1c40f;
                --error-color: #e74c3c;
                --text-color: #ecf0f1;
                --bg-color: #2c3e50;
                --card-bg: #34495e;
                --fish-color: invert(80%) sepia(100%) saturate(100%) hue-rotate(180deg) brightness(100%) contrast(100%);
            }

            /* Theme toggle switch styles */
            .theme-switch-wrapper {
                display: flex;
                align-items: center;
                position: absolute;
                right: 20px;
                top: 20px;
            }

            .theme-switch {
                display: inline-block;
                height: 34px;
                position: relative;
                width: 60px;
            }

            .theme-switch input {
                display: none;
            }

            .slider {
                background-color: #ccc;
                bottom: 0;
                cursor: pointer;
                left: 0;
                position: absolute;
                right: 0;
                top: 0;
                transition: .4s;
                border-radius: 34px;
            }

            .slider:before {
                background-color: #fff;
                bottom: 4px;
                content: "";
                height: 26px;
                left: 4px;
                position: absolute;
                transition: .4s;
                width: 26px;
                border-radius: 50%;
            }

            input:checked + .slider {
                background-color: #66bb6a;
            }

            input:checked + .slider:before {
                transform: translateX(26px);
            }

            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 0;
                background: var(--bg-color);
                color: var(--text-color);
                transition: background-color 0.3s ease, color 0.3s ease;
            }
            br {
                display: block;
                margin: 0px 0;
            }

            .container {
                padding: 20px;
                max-width: 100%;
                margin: 0 auto;
            }

            .graph-container {
                background: var(--card-bg);
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 20px;
                padding: 15px;
                position: relative;
            }

            .info-panel {
                display: flex;
                gap: 20px;
                margin-top: 20px;
            }

            .node-info, .file-contents {
                background: var(--card-bg);
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                padding: 20px;
                flex: 1;
                max-height: 600px;
                overflow-y: auto;
            }

            h1 {
                font-size: 1.5rem;
                margin: 0 0 15px 0;
                color: var(--primary-color);
            }

            details {
                margin: 8px 0;
            }

            details > summary {
                cursor: pointer;
                padding: 8px;
                border-radius: 4px;
                background: var(--bg-color);
                transition: background 0.2s;
            }

            details > summary:hover {
                background: var(--secondary-color);
            }

            details > summary::-webkit-details-marker {
                display: none;
            }

            details > summary:before {
                content: "📁";
                margin-right: 8px;
            }

            details[open] > summary:before {
                content: "📂";
            }

            .file {
                margin: 4px 0;
                padding: 8px;
                border-radius: 4px;
                transition: background 0.2s;
            }

            .file:before {
                content: "📄";
                margin-right: 8px;
            }

            .file:hover {
                background: var(--secondary-color);
                cursor: pointer;
            }

            pre {
                background: var(--card-bg);
                padding: 15px;
                border-radius: 4px;
                font-family: 'Fira Code', 'Consolas', monospace;
                font-size: 0.9rem;
                overflow-x: auto;
                overflow-y: auto;
                max-height: inherit;
                color: var(--text-color);
            }

            .updatemenu-button {
                visibility: hidden;
            }

            .status-running { color: var(--accent-color); }
            .status-success { color: var(--success-color); }
            .status-pending { color: var(--warning-color); }
            .status-failed { color: var(--error-color); }

            .fish-svg {
                pointer-events: none;
                z-index: 10;
            }

            g.infolayer:hover > g:not(:hover) > g > g > rect {
                opacity: .4;
            }
            g.infolayer > g > g > g > rect {
                transition: opacity 0.2s ease-out, filter 0.2s ease-out;
            }
        </style>
        <script>
            // Check for saved theme preference, otherwise use system preference
            const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)');
            //const currentTheme = localStorage.getItem('theme');
            const currentTheme = 'dark';

            if (currentTheme == 'dark') {
                document.documentElement.setAttribute('data-theme', 'dark');
            } else if (currentTheme == 'light') {
                document.documentElement.setAttribute('data-theme', 'light');
            } else if (prefersDarkScheme.matches) {
                document.documentElement.setAttribute('data-theme', 'dark');
            }

            function toggleTheme(e) {
                if (e.target.checked) {
                    document.documentElement.setAttribute('data-theme', 'dark');
                    localStorage.setItem('theme', 'dark');
                } else {
                    document.documentElement.setAttribute('data-theme', 'light');
                    localStorage.setItem('theme', 'light');
                }
            }

            // Add event listener after DOM is loaded
            document.addEventListener('DOMContentLoaded', function() {
                const toggleSwitch = document.querySelector('.theme-switch input[type="checkbox"]');
                const currentTheme = localStorage.getItem('theme');
                
                if (currentTheme == 'dark') {
                    toggleSwitch.checked = true;
                }
                
                toggleSwitch.addEventListener('change', toggleTheme, false);
            });
        </script>
    </head>
    <body>
        <!-- Theme toggle switch 
        <div class="theme-switch-wrapper">
            <label class="theme-switch" for="checkbox">
                <input type="checkbox" id="checkbox" />
                <div class="slider"></div>
            </label>
        </div>
        -->
        <!--[if IE]><script>
        alert("Dash v2.7+ does not support Internet Explorer. Please use a newer browser.");
        </script><![endif]-->
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
            <script src="assets/fish.js"></script>
        </footer>
    </body>
</html>"""


class TaskVisualizer:
    """The class that does the rendering of the task graph.

    Runs alongside the main pipeline and updates the graph interactively.
    """

    def __init__(self, pipeline, debug=False):
        self.pipeline = pipeline
        self.debug = debug  # Add debug flag
        self.status_colors = {
            "failed": "red",
            "success": "blue",
            "running": "green",
            "pending": "gray",
        }
        self.nodes = {}
        # Track previous node states to detect transitions
        self.prev_node_states = {}
        # Track active animations
        self.active_animations = []

        BASE_URL = os.environ.get("VIZ_BASE_URL", "/")

        self.app = dash.Dash("pydatatask", index_string=_default_index, url_base_pathname=BASE_URL)

        self.app.layout = self.generate_layout()
        self.register_callbacks()

        self.request = None
        self.thread = threading.Thread(target=self._thread, daemon=True)
        self.thread.start()

    def do_async(self, coro):
        response = []
        while self.request is None:
            time.sleep(0.05)
        self.request.sync_q.put((coro, response))
        while not response:
            time.sleep(0.05)
        return response[0].sync_q.get()

    def _thread(self):
        asyncio.run(self._async_thread())

    async def _async_thread(self):
        self.request = Queue()
        async with self.pipeline:
            while True:
                thing, response = await self.request.async_q.get()
                response.append(Queue())
                result = await thing
                await response[0].async_q.put(result)
                self.pipeline.cache_flush(soft=True)

    def left_to_right_layout(self, graph):
        # Remove passthrough nodes by reconnecting their parents to their children
        passthrough_nodes = {node for node in graph.nodes if node.name.startswith("passthrough")}
        for node in passthrough_nodes:
            parents = list(graph.predecessors(node))
            children = list(graph.successors(node))
            # Reconnect parents to children
            for parent in parents:
                for child in children:
                    graph.add_edge(parent, child)
            # Remove the passthrough node
            graph.remove_node(node)

        # Function to create a multipartite layout for a graph
        for edge in list(graph.edges):
            if edge[0] == edge[1]:
                graph.remove_edge(*edge)

        levels = {}
        roots = [node for node in graph.nodes if graph.in_degree(node) == 0]  # Find all root nodes

        seen_nodes = set()

        def assign_levels_dfs(node, current_depth):
            if node in seen_nodes:
                return
            seen_nodes.add(node)
            levels[node] = current_depth
            for child in graph.successors(node):
                assign_levels_dfs(child, current_depth + 1)
            seen_nodes.remove(node)

        for root in roots:
            assign_levels_dfs(root, 0)

        # Adjust the layer of each node based on the maximum depth of its predecessors
        for node in graph.nodes:
            if graph.in_degree(node) > 0:  # If the node has predecessors
                max_layer = max(levels.get(pred, 0) for pred in graph.predecessors(node))
                levels[node] = max_layer + 1

        # Add a level attribute to each node for multipartite layout
        for node in graph.nodes:
            graph.nodes[node]["layer"] = levels.get(node, 0)  # Default to layer 0 if not in levels

        # Compute the multipartite layout
        layout = nx.multipartite_layout(graph, subset_key="layer")
        scale_factor = 5  # Increased scale factor
        x_spacing_factor = 0  # Additional spacing between nodes
        y_spacing_factor = 0  # Additional spacing between nodes
        final_layout = {}
        for node, (x, y) in layout.items():
            final_layout[node] = (x * scale_factor + x_spacing_factor, y * scale_factor + y_spacing_factor)

        return final_layout

    @staticmethod
    def generate_layout():
        """Sets up the graph view with the area and the update timeout."""
        graph_layout = dcc.Graph(
            id="network-graph",
            style={
                "width": "100%",
                "height": "70vh",
                "background": "var(--card-bg)",
                "border-radius": "8px",
            },
            config={
                "doubleClick": "reset+autosize",
                "displayModeBar": "hover",
                "modeBarButtonsToRemove": ["select2d", "lasso2d"],
                "showAxisDragHandles": True,
                "displaylogo": False,
                "scrollZoom": False,
                "editable": True,
                "showEditInChartStudio": False,
                "toImageButtonOptions": {
                    "format": "png",
                    "filename": "pipeline_graph",
                },
                "showSendToCloud": False,
                "responsive": True,
                "showTips": False,
                "edits": {
                    "annotationPosition": False,  # Prevent moving annotations
                    "annotationTail": False,  # Prevent editing annotation tails
                    "annotationText": False,  # Prevent editing annotation text
                },
            },
            clear_on_unhover=False,  # Prevent clearing hover data when mouse moves away
        )

        interval_layout = dcc.Interval(id="interval-component", interval=5 * 1000, n_intervals=0)

        return html.Div(
            className="container",
            children=[
                html.H1("Pipeline Visualization", style={"textAlign": "center", "marginBottom": "20px"}),
                html.Div(className="graph-container", children=[graph_layout]),
                html.Div(
                    className="info-panel",
                    children=[
                        html.Div(id="node-info", className="node-info", children=["Select a node to view details"]),
                        html.Div(
                            id="file-contents",
                            className="file-contents",
                            children=["Select a file to view its contents"],
                        ),
                    ],
                ),
                interval_layout,
            ],
        )

    def create_rectangle_shapes(self, pos, width=60, height=30):
        """Renders the pipeline node rectangles."""
        shapes = []
        for _, (x, y) in pos.items():
            shape = {
                "type": "rect",
                "x0": x - width / 2,
                "y0": y - height / 2,
                "x1": x + width / 2,
                "y1": y + height / 2,
                "line": {
                    "color": "blue",
                    "width": 2,
                },
                "fillcolor": "blue",
            }
            shapes.append(shape)
        return shapes

    async def get_task_info(self, nodes):
        """Retrieve the info about a given node from the repositories it is attached to and return it as a dict."""

        async def get_node_info(node):
            return {linkname: len(await link.repo.keys()) for linkname, link in node.links.items()}

        all_node_info = {
            node.name: result
            for node, result in zip(nodes, await asyncio.gather(*(get_node_info(node) for node in nodes)))
        }
        return all_node_info

    def run_async(self, queue, coroutine, *args):
        """Doesn't really need docs lol."""

        async def inner():
            async with self.pipeline:
                return await coroutine(*args)

        result = asyncio.run(inner())
        queue.put(result)

    def populate_all_node_info(self, nodes):
        """Collects a bunch of stuff in a separate subprocess.

        This is PROBABLY done to avoid blocking the main thread? Only @Clasm knows for sure why this was necessary.
        """
        self.nodes = self.do_async(self.get_task_info(nodes))

    @staticmethod
    def generate_file_tree_html(taskname, linkname, jobs, ty):
        """Generates a collapsible file tree for the given path.

        This is used to display the contents of a repository.
        """
        items = []
        for job in jobs:
            identity = {"type": ty, "index": f"{taskname}.{linkname}.{job}"}
            items.append(
                html.Details(
                    [
                        html.Div(
                            [
                                html.P(
                                    job,
                                    id=identity,
                                    style={"padding-left": "20px", "cursor": "pointer"},
                                    className="file",
                                )
                            ],
                            style={"padding-left": "20px"},
                        ),
                    ],
                    open=False,
                )
            )

        return html.Div(items)

    def register_callbacks(self):
        """Registers the callbacks for the dash app."""

        # Add clientside callback to improve node click handling
        self.app.clientside_callback(
            """
            function(clickData) {
                if (!clickData) return null;
                
                // Return the clickData to the server-side callback
                return clickData;
            }
            """,
            Output("network-graph", "clickAnnotationData", allow_duplicate=True),
            Input("network-graph", "clickAnnotationData"),
            prevent_initial_call=True,
        )

        @self.app.callback(
            Output("file-contents", "children"),
            [Input({"type": "file", "index": dash.dependencies.ALL}, "n_clicks")],
            [dash.dependencies.State({"type": "file", "index": dash.dependencies.ALL}, "id")],
        )
        def display_contents(n_clicks, _id):
            # Check which file was clicked
            ctx = dash.callback_context
            if not ctx.triggered:
                return "Select a node to view its repos."
            if not any(n_clicks):
                return "Select a file to view its contents."

            # Get the button that was clicked
            button_id = ctx.triggered[0]["prop_id"].replace(".n_clicks", "")
            # Safely parse the JSON string without using eval()
            button_id_dict = json.loads(button_id.replace("'", '"'))
            taskname, linkname, job = button_id_dict["index"].split(".")
            repo = self.pipeline.tasks[taskname].links[linkname].repo
            file_path = f"{taskname}.{linkname} {job}"

            # Read the file contents
            try:
                if isinstance(repo, BlobRepository):
                    contents = self.do_async(repo.blobinfo(job)).decode("utf-8", errors="replace")
                elif isinstance(repo, MetadataRepository):
                    contents = yaml.safe_dump(self.do_async(repo.info(job)))
                else:
                    contents = "<unreadable repo type>"
                return html.Div(
                    [
                        html.H1(file_path),
                        html.Pre(
                            contents,
                            style={
                                "white-space": "pre-wrap",
                                "word-break": "break-word",
                                "max-height": "calc(100vh - 200px)",  # Dynamic height based on viewport
                                "overflow-y": "auto",  # Enable vertical scrolling
                            },
                        ),
                    ]
                )
            except Exception as e:  # pylint: disable=broad-except
                return html.Div(
                    [
                        html.H1(file_path),
                        html.Pre(
                            f"Could not read file: {e}", style={"white-space": "pre-wrap", "word-break": "break-word"}
                        ),
                    ]
                )

        @self.app.callback(
            Output("node-info", "children"),
            [Input("network-graph", "clickAnnotationData")],
        )
        def annotation_click(clickData):
            if not clickData:
                raise dash.exceptions.PreventUpdate

            # Extract the node name from the HTML text (everything before the <br> tag)
            try:
                name = clickData["annotation"]["text"].split("<br>")[0]

                # Find the matching node in the pipeline
                for node in self.pipeline.task_graph.nodes():
                    if node.name == name:
                        break
                else:
                    return html.Div("Node not found in pipeline")

                children: List[Any] = [
                    html.H1(node.name),
                ]

                # Add repository information
                for link in node.links:
                    children.append(html.P(f"{link}<{node.links[link].repo.__class__.__name__}>:"))
                    keys = self.do_async(node.links[link].repo.keys())
                    children.append(
                        self.generate_file_tree_html(
                            node.name,
                            link,
                            keys,
                            (
                                "file"
                                if isinstance(node.links[link].repo, (BlobRepository, MetadataRepository))
                                else "unknown"
                            ),
                        )
                    )

                output = html.Div(children)
                return output

            except Exception as e:  # Handle any errors gracefully
                if self.debug:
                    return html.Div([html.H1("Error processing click"), html.Pre(str(e)), html.Pre(str(clickData))])
                return html.Div("Error processing click. Please try again.")

        @self.app.callback(Output("network-graph", "figure"), [Input("interval-component", "n_intervals")])
        def update_graph(n):
            pl = self.pipeline
            new_graph = pl.task_graph
            pos = self.left_to_right_layout(new_graph)

            fig = go.Figure()
            annotations = []
            self.populate_all_node_info(list(pos.keys()))

            # Get current theme from document
            is_dark_mode = 'document.documentElement.getAttribute("data-theme") === "dark"'

            # Separate edges into inactive and active for z-ordering
            inactive_edges = []
            active_edges = []

            for edge in new_graph.edges():
                if edge[0] not in pos or edge[1] not in pos:
                    continue
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]

                # Check if source node is running
                source_results = self.nodes[edge[0].name]
                is_active = source_results["live"] > 0

                edge_trace = go.Scatter(
                    x=[x0, x1],
                    y=[y0, y1],
                    mode="lines",
                    line=dict(
                        width=2,
                        color=f"{'#ecf0f1' if is_active else '#2c3e50'}"
                        if is_dark_mode
                        else f"{'#95a5a6' if is_active else '#d5dbdb'}",
                    ),
                    hoverinfo="none",
                    showlegend=False,
                )

                if is_active:
                    active_edges.append(edge_trace)
                else:
                    inactive_edges.append(edge_trace)

            # Add inactive (darker) edges first, so they appear below
            for edge_trace in inactive_edges:
                fig.add_trace(edge_trace)

            # Calculate node dimensions based on text length
            base_node_width = 120  # Reduced base width
            base_node_height = 18  # Reduced base height
            char_width = 7  # Reduced character width

            node_dimensions = {}
            for node in new_graph.nodes():
                text_width = len(node.name) * char_width
                node_width = max(base_node_width, text_width)
                node_dimensions[node] = {"width": node_width, "height": base_node_height}

            # Custom node colors and styles with improved contrast
            node_styles = {
                "running": {
                    "color": "#2ecc71",  # Light green
                    "border": "#27ae60",  # Darker green border
                    "hover_bg": "#27ae60",
                    "hover_text": "#ffffff",
                },
                "success": {
                    "color": "#3498db",  # Blue
                    "border": "#2980b9",
                    "hover_bg": "#2980b9",
                    "hover_text": "#ffffff",
                },
                "pending": {
                    "color": "rgba(150, 150, 150, 0.75)",  # Darker grey with 0.75 opacity
                    "border": "rgba(100, 100, 100, 0.75)",  # Darker border grey with 0.75 opacity
                    "hover_bg": "#7f8c8d",
                    "hover_text": "#ffffff",
                },
                "failed": {
                    "color": "#e74c3c",  # Red
                    "border": "#c0392b",
                    "hover_bg": "#c0392b",
                    "hover_text": "#ffffff",
                },
                "mixed": {
                    "color": "#9b59b6",  # Purple
                    "border": "#8e44ad",
                    "hover_bg": "#8e44ad",
                    "hover_text": "#ffffff",
                },
            }

            # Draw nodes
            for node, (x, y) in pos.items():
                results = self.nodes[node.name]
                total = results["live"] + results["done"]

                # Determine node color based on state
                if total == 0:
                    bgcolor = node_styles["pending"]["color"]  # Lighter grey for never run nodes
                    border_color = node_styles["pending"]["border"]
                    border_width = 2
                else:
                    has_success = results["success"] > 0
                    has_failed = (results["done"] - results["success"]) > 0
                    is_running = results["live"] > 0

                    if is_running and not has_success and not has_failed:
                        bgcolor = node_styles["running"]["color"]  # Green for running-only
                        border_color = node_styles["running"]["border"]
                        border_width = 2
                    elif has_success and has_failed:
                        bgcolor = node_styles["mixed"]["color"]  # Purple for mixed success/failure
                        border_color = node_styles["mixed"]["border"]
                        border_width = 2
                    elif has_success:
                        bgcolor = node_styles["success"]["color"]  # Blue for success
                        border_color = node_styles["success"]["border"]
                        border_width = 2
                    elif has_failed:
                        bgcolor = node_styles["failed"]["color"]  # Red for failure
                        border_color = node_styles["failed"]["border"]
                        border_width = 2
                    else:
                        bgcolor = node_styles["pending"]["color"]  # Lighter grey for never run nodes
                        border_color = node_styles["pending"]["border"]
                        border_width = 2

                    # Add green border for running nodes that have other states
                    if is_running and (has_success or has_failed):
                        border_color = node_styles["running"]["border"]  # Green border
                        border_width = 3  # Thicker border for running nodes

                # Create status counters text
                status_text = []
                if results["live"] > 0:
                    status_text.append(f"🔄 {results['live']}")
                if results["success"] > 0:
                    status_text.append(f"✓ {results['success']}")
                failed_count = results["done"] - results["success"]
                if failed_count > 0:
                    status_text.append(f"✗ {failed_count}")
                if not status_text and (
                    results["live"] > 0 or results["done"] > 0
                ):  # Only show pending for previously active nodes
                    status_text.append("⋯")
                status_line = " | ".join(status_text) if status_text else ""

                # Combine task name with status counters
                display_text = f"{node.name}<br><span style='font-size: 8px'>{status_line}</span>"

                node_dims = node_dimensions[node]
                annotations.append(
                    {
                        "x": x,
                        "y": y,
                        "xref": "x",
                        "yref": "y",
                        "text": display_text,
                        "showarrow": False,
                        "font": {"size": 12, "color": "white", "family": "Inter, sans-serif"},
                        "bgcolor": bgcolor,
                        "bordercolor": border_color,
                        "borderwidth": border_width,
                        "borderpad": 2,
                        "width": node_dims["width"],
                        "height": node_dims["height"] + 10,
                        "align": "center",
                        "hovertext": "<br>".join(f"{k}: {v}" for k, v in self.nodes[node.name].items()),
                        "hoverlabel": {
                            "bgcolor": bgcolor,  # Match parent node color
                            "font": {
                                "family": "Inter, sans-serif",
                                "size": 14,
                                "color": "white",  # Always white text for contrast
                            },
                            "bordercolor": border_color,
                        },
                        "captureevents": True,  # Ensure annotations capture click events
                        "clicktoshow": False,  # Don't toggle visibility on click
                        "opacity": 1,  # Full opacity
                        "standoff": 0,  # No standoff
                    }
                )

            # Add active (lighter) edges last, so they appear on top
            for edge_trace in active_edges:
                fig.add_trace(edge_trace)

            fig.update_layout(
                title="",
                showlegend=False,
                margin={"b": 10, "l": 10, "r": 10, "t": 10},
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                xaxis={
                    "showgrid": False,
                    "zeroline": False,
                    "showticklabels": False,
                    "showline": False,
                    "fixedrange": True,  # Lock axis
                    "visible": False,
                    "ticks": "",
                },
                yaxis={
                    "showgrid": False,
                    "zeroline": False,
                    "showticklabels": False,
                    "showline": False,
                    "fixedrange": True,  # Lock axis
                    "visible": False,
                    "ticks": "",
                },
                hoverlabel={
                    "font_family": "Inter, sans-serif",
                    "font_size": 14,
                },
                annotations=annotations,
                dragmode=False,  # Disable dragging
                modebar={
                    "orientation": "v",
                    "bgcolor": "rgba(255, 255, 255, 0.7)",
                    "color": "#2c3e50",
                    "activecolor": "#3498db",
                },
                autosize=True,
                shapes=[],  # Clear any auto-generated shapes
                clickmode="event+select",  # Enable both click events and selection
            )

            return fig


def run_viz(pipeline, host, port, debug=False):
    """Entrypoint for "pd viz".

    Starts the visualizer and runs the dash server.
    """
    tv = TaskVisualizer(pipeline, debug=debug)
    try:
        tv.app.run(debug=False, host=host, port=port)
    except KeyboardInterrupt:
        pass
