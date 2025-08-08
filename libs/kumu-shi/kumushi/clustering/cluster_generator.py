from kumushi.data import Program, PoICluster


class ClusterGenerator:
    def __init__(self, program: Program, max_cluster_size: int = 8, max_clusters: int = 10):
        self._program = program
        self._max_cluster_size = max_cluster_size
        self._max_clusters = max_clusters

        # output values
        self.clusters: list[PoICluster] = []

    def analyze(self):
        self._analyze()

    def _analyze(self):
        raise NotImplementedError()