// Data model classes for pipeline state, corresponding to Python dataclasses in vizualize.py

/**
 * @enum {string}
 * Node status values, matching Python NodeStatus Enum
 */
export const NodeStatus = Object.freeze({
    RUNNING: 'running',
    RUNNING_FAILED: 'running_failed',
    RUNNING_MIXED: 'running_mixed',
    SUCCESS: 'success',
    FAILED: 'failed',
    MIXED: 'mixed',
    PENDING: 'pending',
});

/**
 * Node statistics, matching Python NodeStats
 */
export class NodeStats {
    /**
     * @param {object} obj
     * @param {number} obj.live
     * @param {number} obj.success
     * @param {number} obj.failed
     * @param {number} obj.timeout
     * @param {number} obj.oomkilled
     * @param {number} obj.pending
     * @param {number} obj.total
     */
    constructor({ live = 0, success = 0, failed = 0, timeout = 0, oomkilled = 0, pending = 0, total = 0 } = {}) {
        this.live = live;
        this.success = success;
        this.failed = failed;
        this.timeout = timeout;
        this.oomkilled = oomkilled;
        this.pending = pending;
        this.total = total;
        
        // Debug logging for new fields
        if (timeout > 0 || oomkilled > 0) {
            console.log('[NODESTATS_DEBUG] Creating NodeStats with timeout:', timeout, 'oomkilled:', oomkilled);
        }
    }
}

/**
 * Node information, matching Python NodeInfo
 */
export class NodeInfo {
    /**
     * @param {object} obj
     * @param {string} obj.id
     * @param {string} obj.name
     * @param {string} obj.status
     * @param {NodeStats|object} obj.stats
     * @param {Object<string, number>} obj.repositories
     * @param {string|Date} obj.last_updated
     * @param {object|null} obj.metadata
     */
    constructor({ id, name, status, stats, repositories = {}, last_updated, metadata = null }) {
        this.id = id;
        this.name = name;
        this.status = status;
        this.stats = stats instanceof NodeStats ? stats : new NodeStats(stats);
        this.repositories = repositories;
        this.last_updated = last_updated ? new Date(last_updated) : null;
        this.metadata = metadata;
    }
}

/**
 * Extended node information, matching Python ExtendedNodeInfo
 */
export class ExtendedNodeInfo extends NodeInfo {
    /**
     * @param {object} obj
     * @param {string} obj.id
     * @param {string} obj.name
     * @param {string} obj.status
     * @param {NodeStats|object} obj.stats
     * @param {Object<string, number>} obj.repositories
     * @param {string|Date} obj.last_updated
     * @param {object|null} obj.metadata
     * @param {string} obj.label
     * @param {string} obj.color
     * @param {string} obj.borderColor
     */
    constructor({ id, name, status, stats, repositories = {}, last_updated, metadata = null, label, color, borderColor }) {
        super({ id, name, status, stats, repositories, last_updated, metadata });
        this.label = label;
        this.color = color;
        this.borderColor = borderColor;
    }
}

/**
 * Edge information, matching Python EdgeInfo
 */
export class EdgeInfo {
    /**
     * @param {object} obj
     * @param {string} obj.source
     * @param {string} obj.target
     * @param {boolean} obj.active
     * @param {number} obj.flow_rate
     */
    constructor({ source, target, active = false, flow_rate = 0.0 }) {
        this.source = source;
        this.target = target;
        this.active = active;
        this.flow_rate = flow_rate;
    }
}

/**
 * File information, matching Python FileInfo
 */
export class FileInfo {
    /**
     * @param {object} obj
     * @param {string} obj.path
     * @param {string} obj.name
     * @param {string} obj.repo
     * @param {number} obj.size
     * @param {string|Date} obj.modified
     * @param {string} obj.type
     */
    constructor({ path, name, repo, size = 0, modified, type = 'unknown' }) {
        this.path = path;
        this.name = name;
        this.repo = repo;
        this.size = size;
        this.modified = modified ? new Date(modified) : null;
        this.type = type;
    }
}

/**
 * Pipeline state, matching the structure returned by Python PipelineCache.get_state()
 */
export class PipelineState {
    /**
     * @param {object} obj
     * @param {NodeInfo[]|object[]} obj.nodes
     * @param {EdgeInfo[]|object[]} obj.edges
     * @param {string} obj.task_name
     * @param {string} obj.task_id
     * @param {string|Date} obj.last_update
     */
    constructor({ nodes = [], edges = [], task_name = '', task_id = '', last_update = null } = {}) {
        this.nodes = nodes.map(n => n instanceof NodeInfo ? n : new NodeInfo(n));
        this.edges = edges.map(e => e instanceof EdgeInfo ? e : new EdgeInfo(e));
        this.task_name = task_name;
        this.task_id = task_id;
        this.last_update = last_update ? new Date(last_update) : null;
    }
} 

/**
 * Why ready result, matching the structure returned by Python WhyReadyResult
 */
export class WhyReadyResult {
    /**
     * @param {object} obj
     * @param {string} obj.stdout
     * @param {string} obj.stderr
     * @param {string} obj.error
     */
    constructor({ stdout = '', stderr = '', error = '' } = {}) {
        this.stdout = stdout;
        this.stderr = stderr;
        this.error = error;
    }
}