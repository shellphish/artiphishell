// Graph management module
import { getNodeColor, getNodeBorderColor } from '../utils/colors.js';
import { updateFishAnimations } from './animations.js';
import { PipelineState, NodeInfo, EdgeInfo, ExtendedNodeInfo } from './models.js';

let cy = null;
let hasFitOnce = false;
let nodePositions = {};
let cyto_zoom_fit_padding = window.innerWidth <= 768 ? 300 : 400;
let node_zoom_fit_padding = window.innerWidth <= 768 ? 100 : 200;

// Calculate appropriate padding based on graph size
function calculatePadding(node) {
    if (!cy || !node) return node_zoom_fit_padding;
    
    // Get the bounding box of the node
    const nodeBox = node.boundingBox();
    const graphBox = cy.elements().boundingBox();
    
    // Calculate the ratio of node size to graph size
    const nodeSize = Math.max(nodeBox.w, nodeBox.h);
    const graphSize = Math.max(graphBox.w, graphBox.h);
    const ratio = nodeSize / graphSize;
    
    // Adjust padding based on the ratio
    // For larger nodes relative to graph size, use smaller padding
    // For smaller nodes relative to graph size, use larger padding
    const basePadding = window.innerWidth <= 768 ? 150 : 175;
    const adjustedPadding = Math.max(basePadding, Math.min(basePadding * 3, basePadding / ratio));
    
    return adjustedPadding;
}

// Update padding on window resize
window.addEventListener('resize', () => {
    const newPadding = window.innerWidth <= 768 ? 300 : 400;
    if (newPadding !== cyto_zoom_fit_padding) {
        cyto_zoom_fit_padding = newPadding;
    }
});

const klay_layout = {
    name: 'klay',
    klay: {
        addUnnecessaryBendpoints: false,
        aspectRatio: 1.6,
        borderSpacing: 10,
        compactComponents: false,
        crossingMinimization: 'LAYER_SWEEP',
        cycleBreaking: 'GREEDY',
        direction: 'RIGHT',
        edgeRouting: 'ORTHOGONAL',
        edgeSpacingFactor: 0.1,
        feedbackEdges: false,
        fixedAlignment: 'NONE',
        inLayerSpacingFactor: 0.5,
        layoutHierarchy: false,
        linearSegmentsDeflectionDampening: 0.3,
        mergeEdges: false,
        mergeHierarchyCrossingEdges: true,
        nodeLayering: 'NETWORK_SIMPLEX',
        nodePlacement: 'LINEAR_SEGMENTS',
        randomizationSeed: 1,
        routeSelfLoopInside: false,
        separateConnectedComponents: true,
        spacing: 10,
        thoroughness: 7
    },
    fit: true,
    padding: 50,
    animate: true,
    animationDuration: 500
};

/**
 * Initializes the Cytoscape graph
 */
export function initCytoscape() {
    cytoscape.use(window.cytoscapeKlay);
    cy = cytoscape({
        container: document.getElementById('cy'),
        style: [
            {
                selector: 'node',
                style: {
                    'background-color': 'data(color)',
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'width': 'label',
                    'height': 'label',
                    'padding': 20,
                    'font-size': 14,
                    'color': '#fff',
                    'text-outline-width': 2,
                    'text-outline-color': 'data(color)',
                    'shape': 'roundrectangle',
                    'border-width': 2,
                    'border-color': 'data(borderColor)',
                    'transition-property': 'background-color, border-color, border-width',
                    'transition-duration': '0.3s',
                    'text-wrap': 'wrap',
                    'text-max-width': '200px',
                    'text-justification': 'center'
                }
            },
            {
                selector: 'node:selected',
                style: {
                    'border-color': '#f39c12',
                    'border-width': 4
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#95a5a6',
                    'target-arrow-color': '#95a5a6',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'control-point-step-size': 40,
                    'transition-property': 'line-color, width',
                    'transition-duration': '0.3s'
                }
            },
            {
                selector: 'edge[active="true"]',
                style: {
                    'line-color': '#3498db',
                    'target-arrow-color': '#3498db',
                    'width': 3,
                    'z-index': 999
                }
            }
        ],
        layout: klay_layout,
        userZoomingEnabled: true,
        userPanningEnabled: true,
        minZoom: 0.1,
        maxZoom: 2.5,
        wheelSensitivity: 0.1
    });

    setupEventListeners();
    return cy;
}

function setupEventListeners() {
    // Node click handler with zoom
    cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        const event = new CustomEvent('nodeSelected', { detail: { nodeId: node.id() } });
        document.dispatchEvent(event);
        
        // Zoom to the clicked node with dynamic padding
        cy.animate({
            fit: {
                eles: node,
                padding: calculatePadding(node)
            },
            duration: 500
        });
    });

    // Background click handler
    cy.on('tap', function(evt) {
        if (evt.target === cy) {
            const event = new CustomEvent('nodeDeselected');
            document.dispatchEvent(event);
        }
    });

    // Persist node position on drag
    cy.on('position', 'node', function(evt) {
        const node = evt.target;
        nodePositions[node.id()] = { x: node.position('x'), y: node.position('y') };
    });
}

/**
 * Updates the graph with a new pipeline state
 * @param {PipelineState} pipelineState - The new pipeline state
 */
export function updateGraph(pipelineState) {
    if (!cy || !pipelineState) return;

    // Store current viewport state
    const currentZoom = cy.zoom();
    const currentPan = cy.pan();
    
    // Get existing elements
    /** @type {Map<string, ExtendedNodeInfo>} */
    const existingNodes = new Map();
    /** @type {Map<string, EdgeInfo>} */
    const existingEdges = new Map();
    
    cy.nodes().forEach(node => {
        existingNodes.set(node.id(), node);
    });
    
    cy.edges().forEach(edge => {
        existingEdges.set(edge.id(), edge);
    });

    // Prepare new elements
    /** @type {Map<string, ExtendedNodeInfo>} */
    const newNodes = new Map();
    /** @type {Map<string, EdgeInfo>} */
    const newEdges = new Map();
    
    // Add nodes
    pipelineState.nodes.forEach(node => {
        const nodeData = {
            id: node.id,
            label: `${node.name}\n\n🔄 ${node.stats.live} | ✓ ${node.stats.success} | ✗ ${node.stats.failed}`,
            color: getNodeColor(node.status),
            borderColor: getNodeBorderColor(node.status),
            ...node
        };
        newNodes.set(node.id, nodeData);
    });

    // Add edges
    pipelineState.edges.forEach(edge => {
        const edgeData = {
            id: `${edge.source}-${edge.target}`,
            source: edge.source,
            target: edge.target,
            active: edge.active.toString()
        };
        newEdges.set(edgeData.id, edgeData);
    });

    // Remove elements that no longer exist
    existingNodes.forEach((node, id) => {
        if (!newNodes.has(id)) {
            node.remove();
        }
    });
    
    existingEdges.forEach((edge, id) => {
        if (!newEdges.has(id)) {
            edge.remove();
        }
    });

    // Update or add new elements
    newNodes.forEach((data, id) => {
        if (existingNodes.has(id)) {
            // Update existing node only if data has changed
            const node = existingNodes.get(id);
            const currentData = node.data();

            const hasChanged = JSON.stringify(currentData) !== JSON.stringify(data);
            
            if (hasChanged) {
                node.data(data);
                // Restore position if stored
                if (nodePositions[id]) {
                    node.position(nodePositions[id]);
                }
            }
        } else {
            // Add new node
            cy.add({ data });
            // Restore position if stored
            if (nodePositions[id]) {
                cy.getElementById(id).position(nodePositions[id]);
            }
        }
    });

    newEdges.forEach((data, id) => {
        if (existingEdges.has(id)) {
            // Update existing edge only if data has changed
            const edge = existingEdges.get(id);
            const currentData = edge.data();
            const hasChanged = JSON.stringify(currentData) !== JSON.stringify(data);
            
            if (hasChanged) {
                edge.data(data);
            }
        } else {
            // Add new edge
            cy.add({ data });
        }
    });

    // Only run layout if there are new elements or removed elements
    const hasNewElements = newNodes.size > existingNodes.size || newEdges.size > existingEdges.size;
    const hasRemovedElements = newNodes.size < existingNodes.size || newEdges.size < existingEdges.size;

    if (hasNewElements || hasRemovedElements) {
        // Use klay layout for proper separation and no overlap
        cy.layout(klay_layout).run();
    }

    // Initial fit only once
    if (!hasFitOnce) {
        hasFitOnce = true;
        // Fit the graph to the viewport
        cy.fit(cy.elements(), 50);
    }

    // Restore viewport state (if not initial fit)
    if (hasFitOnce) {
        cy.zoom(currentZoom);
        cy.pan(currentPan);
    }

    // Update fish animations
    updateFishAnimations(cy, pipelineState);
}

export function getCytoscape() {
    return cy;
}

export function navigateToNode(nodeId) {
    const node = cy.getElementById(nodeId);
    if (node) {
        // Unselect any previously selected nodes
        cy.$(':selected').unselect();
        
        // Select the new node
        node.select();
        
        // Zoom to the node with dynamic padding
        cy.animate({
            fit: {
                eles: node,
                padding: calculatePadding(node)
            },
            duration: 500
        });
        
        // Show node details
        const event = new CustomEvent('nodeSelected', { detail: { nodeId } });
        document.dispatchEvent(event);
    }
} 