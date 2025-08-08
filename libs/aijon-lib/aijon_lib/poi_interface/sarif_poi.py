from pathlib import Path

from .poi_poi import POI


class SarifPOI(POI):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_poi(self, sarif_report: Path):
        """Add a Point of Interest (POI) to the POI list.

        Args:
            sarif_report (Path): The path to the SARIF report file.
        """
        assert sarif_report.is_file(), f"File {sarif_report} does not exist."

        poi = SarifPOI.parse_poi_from_sarif(sarif_report)
        self._pois.append(poi)

    @staticmethod
    def parse_poi_from_sarif(sarif_report: Path) -> dict:
        """Parse the SARIF report to extract Points of Interest (POIs).

        Args:
            sarif_report (Path): The path to the SARIF report file.

        Returns:
            dict: A dictionary representing the POI extracted from the SARIF report.
        """
        raise NotImplementedError("Not implemented yet.")
