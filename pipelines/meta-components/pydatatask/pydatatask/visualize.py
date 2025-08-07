"""Visualizes the pipeline live using dash to plot the graph and update the status of each node over time."""

from typing import Any, DefaultDict, Dict, List
from collections import defaultdict
import asyncio
import json
import os
import queue
import threading
import time

from dash import dcc, html
from dash.dependencies import Input, Output
from janus import Queue
import dash
import networkx as nx
import plotly.figure_factory as ff
import plotly.graph_objects as go
import yaml

from .repository import (
    BlobRepository,
    DirectoryRepository,
    FileRepositoryBase,
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
          details > summary {
            cursor: pointer;
          }

          details > summary::-webkit-details-marker {
            display: none;
          }

          details > summary:before {
            content: "📁 ";
          }

          details[open] > summary:before {
            content: "📂 ";
          }

          .file:before {
            content: "📄 ";
          }

          .file {
            margin: 0;
          }
        </style>
    </head>
    <body>
        <!--[if IE]><script>
        alert("Dash v2.7+ does not support Internet Explorer. Please use a newer browser.");
        </script><![endif]-->
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>"""


class TaskVisualizer:
    """The class that does the rendering of the task graph.

    Runs alongside the main pipeline and updates the graph interactively.
    """

    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.status_colors = {
            "failed": "red",
            "success": "blue",
            "running": "green",
            "pending": "gray",
        }
        self.nodes = {}

        self.app = dash.Dash("pydatatask", index_string=_default_index)
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
                self.pipeline.cache_flush()

    def left_to_right_layout(self, G):
        """This doesn't really need docs, does it?"""
        pos = nx.nx_agraph.graphviz_layout(G, prog="dot", args="-Grankdir=LR -Gsplines=ortho")
        return pos

    @staticmethod
    def generate_layout():
        """Sets up the graph view with the area and the update timeout."""
        graph_layout = dcc.Graph(
            id="network-graph", style={"width": "100%", "height": "90vh"}, config={"doubleClick": "reset+autosize"}
        )
        interval_layout = dcc.Interval(id="interval-component", interval=5 * 1000, n_intervals=0)  # in milliseconds
        style = {"width": "100%", "height": "80vh", "margin": "0", "padding": "0"}

        file_divs = html.Div(
            [
                html.Div(id="node-info", style={"width": "auto", "display": "inline-block"}),
                html.Div(
                    id="file-contents",
                    style={"width": "auto", "display": "inline-block", "marginLeft": "20px", "marginRight": "auto"},
                ),
            ],
            style={"display": "flex", "justifyContent": "space-between"},
        )

        return html.Div([graph_layout, file_divs, interval_layout], style=style)

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

    def create_quiver_plot(self, G, pos):
        """Currently unused AFAICT.

        Can probably be removed.
        """
        edge_x = []
        edge_y = []
        dx = []
        dy = []

        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.append(x0)
            edge_y.append(y0)
            dx.append(x1 - x0)
            dy.append(y1 - y0)

        quiver = ff.create_quiver(
            edge_x, edge_y, dx, dy, scale=1, arrow_scale=0.1, line={"width": 0.8, "color": "#888"}
        )
        return quiver.data[0]

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
                                "max-height": "500px",
                                "overflow-y": "auto",
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
            Output("node-info", "children"),  # Assuming 'url' is the ID of a dcc.Location component
            [Input("network-graph", "clickAnnotationData")],
        )
        def annotation_click(clickData):
            if not clickData:
                raise dash.exceptions.PreventUpdate
            name = clickData["annotation"]["text"]
            for node in self.pipeline.task_graph.nodes():
                if node.name == name:
                    break
            else:
                return ""
            children: List[Any] = [
                html.H1(node.name),
            ]
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

        @self.app.callback(Output("network-graph", "figure"), [Input("interval-component", "n_intervals")])
        def update_graph(n):  # pylint: disable=unused-argument
            pl = self.pipeline
            new_graph = pl.task_graph
            pos = self.left_to_right_layout(new_graph)

            fig = go.Figure()
            annotations = []
            self.populate_all_node_info(list(pos.keys()))

            for node, (x, y) in pos.items():
                results = self.nodes[node.name]
                any_failed = results["success"] != results["done"]
                if results is not None:
                    if results["live"] > 0:
                        node_color = self.status_colors["running"]
                    elif results["done"] > 0:
                        node_color = self.status_colors["success"]
                    else:
                        node_color = self.status_colors["pending"]
                else:
                    node_color = self.status_colors["pending"]

                border_color = "red" if any_failed else "black"
                annotations.append(
                    {
                        "x": x,
                        "y": y,
                        "xref": "x",
                        "yref": "y",
                        "text": node.name,
                        "showarrow": False,
                        "font": {"size": 14, "color": "white"},
                        "bgcolor": node_color,
                        "bordercolor": border_color,
                        "borderwidth": 2,
                        "borderpad": 4,
                        "hovertext": "<br>".join(f"{k}:{v}" for k, v in self.nodes[node.name].items()),
                    }
                )

            for edge in new_graph.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]

                if edge[0] in self.nodes and self.nodes[edge[0].name]["live"] > 0:
                    line_color = self.status_colors["running"]
                elif edge[0] in self.nodes and self.nodes[edge[0].name]["done"] > 0:
                    line_color = self.status_colors["success"]
                else:
                    line_color = self.status_colors["pending"]

                max_size = max(x for x in self.nodes[edge[0].name].values() if isinstance(x, int))
                width = max(max_size.bit_length(), 1)

                fig.add_trace(
                    go.Scatter(
                        x=[x0, x1, None], y=[y0, y1, None], line={"width": width, "color": line_color}, mode="lines"
                    )
                )

            node_x = [pos[node][0] for node in new_graph.nodes()]
            node_y = [pos[node][1] for node in new_graph.nodes()]

            fig.add_trace(go.Scatter(x=node_x, y=node_y, mode="text", visible=False))

            fig.update_layout(
                title="pydatatask visualizer",
                showlegend=False,
                uirevision="some-constant-value",
                margin={"b": 0, "l": 0, "r": 0, "t": 40},
                xaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
                yaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
                hoverlabel={"font_color": "white", "font_size": 16},
                annotations=annotations,
            )

            return fig


def run_viz(pipeline, host, port):
    """Entrypoint for "pd viz".

    Starts the visualizer and runs the dash server.
    """
    tv = TaskVisualizer(pipeline)
    try:
        tv.app.run_server(debug=True, host=host, port=port)
    except KeyboardInterrupt:
        pass
