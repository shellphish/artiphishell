import yaml
from pathlib import Path
from typing import Generator

from .poi_poi import POI


class CodeSwipePOI(POI):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_poi(self, codeswipe_report: Path):
        """Add a Point of Interest (POI) to the POI list.

        Args:
            codeswipe_report (Path): The path to the CodeSwipe report.
        """
        assert codeswipe_report.is_file(), f"File {codeswipe_report} does not exist."

        all_pois = []
        for poi in CodeSwipePOI.parse_poi_from_codeswipe_report(codeswipe_report):
            all_pois.append(poi)

        limit = min(100, len(all_pois))
        self._pois.extend(
            sorted(all_pois, key=lambda x: x["priority_score"], reverse=True)[
                :limit
            ]
        )

    @staticmethod
    def parse_poi_from_codeswipe_report(report: Path) -> Generator[dict, None, None]:
        """Parse the patch to extract Points of Interest (POIs).

        Args:
            report (Path): The path to the CodeSwipe report.

        Returns:
            dict: A dictionary representing the POI extracted from the patch.
        """
        data = yaml.safe_load(report.read_text())

        all_pois = data.get("ranking", [])

        for thing in all_pois:
            poi_data = {
                "file_name": thing["filename"],
                "function_index_key": thing["function_index_key"],
                "metadata": thing["metadata"],
                "priority_score": thing["priority_score"],
            }

            yield poi_data
