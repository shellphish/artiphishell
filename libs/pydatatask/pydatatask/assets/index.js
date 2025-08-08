// Global state
let cy = null;
let ws = null;
let currentView = 'graph';
let selectedNode = null;
let pipelineState = null;
let nodeDetails = {};
let nodeFiles = {};
let activeTab = 'details';
let theme = 'dark';
let fishAnimations = new Map();
let fishProgress = new Map(); // Store fish progress between updates
let animationFrame = null;
let hasFitOnce = false;
let compactSearch = '';
let expandedGroups = {};
let nodePositions = {};
let cyto_zoom_fit_padding = 900;
let repoFileFilters = {};
let connectionFilters = {
    incoming: '',
    outgoing: ''
};
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 10;
const RECONNECT_DELAY = 5000; // 5 seconds
let reconnectTimeout = null;

// Initialize Cytoscape
function initCytoscape() {
    cytoscape.use(window.cytoscapeDagre);
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
                    'border-color': '#2c3e50',
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
        layout: {
            name: 'dagre',
            rankDir: 'LR',
            nodeSep: 20,
            rankSep: 450,
            edgeSep: 10,
            ranker: 'network-simplex',
            padding: 50,
            animate: true,
            animationDuration: 500,
            fit: false // Prevent auto-fitting after layout
        },
        userZoomingEnabled: true,
        userPanningEnabled: true,
        minZoom: 0.1,
        maxZoom: 2.5,
        wheelSensitivity: 0.1
    });

    // Add zoom controls
    const zoomControls = document.createElement('div');
    zoomControls.className = 'zoom-controls';
    zoomControls.innerHTML = `
        <button onclick="cy.zoom(cy.zoom() * 1.2)">+</button>
        <button onclick="cy.zoom(cy.zoom() * 0.8)">-</button>
        <button id="fit-btn">Reset</button>
    `;
    document.getElementById('cy').appendChild(zoomControls);

    // Fit button logic
    const fitBtn = zoomControls.querySelector('#fit-btn');
    fitBtn.addEventListener('click', () => {
        if (!hasFitOnce) {
            // cy.fit(50);
            hasFitOnce = true;
            fitBtn.disabled = true;
        } else {
            cy.fit(50);
        }
    });

    // Node click handler with zoom
    cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        selectedNode = node.id();
        showNodeDetails(selectedNode);
        
        // Zoom to the clicked node with less zoom
        cy.animate({
            fit: {
                eles: node,
                padding: cyto_zoom_fit_padding
            },
            duration: 500
        });
    });

    // Background click handler
    cy.on('tap', function(evt) {
        if (evt.target === cy) {
            selectedNode = null;
            closeDetails();
        }
    });

    // Persist node position on drag
    cy.on('position', 'node', function(evt) {
        const node = evt.target;
        nodePositions[node.id()] = { x: node.position('x'), y: node.position('y') };
    });
}

// WebSocket connection
function connectWebSocket() {
    // Clear any existing reconnection timeout
    if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
    }

    // Don't try to connect if we've exceeded max attempts
    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        console.error('Max reconnection attempts reached');
        updateConnectionStatus(false, 'Connection failed after multiple attempts');
        return;
    }

    const clientId = `client-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/${clientId}`;
    console.log("Attempting to connect to:", wsUrl);

    try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            console.log('Connected to pipeline');
            reconnectAttempts = 0; // Reset reconnect attempts on successful connection
            updateConnectionStatus(true);
            document.querySelector('.loading').style.display = 'none';
        };

        ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                handleMessage(message);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            updateConnectionStatus(false, 'Connection error occurred');
        };

        ws.onclose = (event) => {
            console.log('Disconnected from pipeline:', event.code, event.reason);
            let errorMessage = 'Disconnected from server';
            
            // Add more specific error messages based on close code
            switch (event.code) {
                case 1000:
                    errorMessage = 'Connection closed normally';
                    break;
                case 1001:
                    errorMessage = 'Server is going away';
                    break;
                case 1002:
                    errorMessage = 'Protocol error';
                    break;
                case 1003:
                    errorMessage = 'Unsupported data';
                    break;
                case 1005:
                    errorMessage = 'No status received';
                    break;
                case 1006:
                    errorMessage = 'Connection closed abnormally';
                    break;
                case 1007:
                    errorMessage = 'Invalid frame payload data';
                    break;
                case 1008:
                    errorMessage = 'Policy violation';
                    break;
                case 1009:
                    errorMessage = 'Message too big';
                    break;
                case 1010:
                    errorMessage = 'Missing extension';
                    break;
                case 1011:
                    errorMessage = 'Internal server error';
                    break;
                case 1012:
                    errorMessage = 'Service restart';
                    break;
                case 1013:
                    errorMessage = 'Try again later';
                    break;
                case 1014:
                    errorMessage = 'Bad gateway';
                    break;
                case 1015:
                    errorMessage = 'TLS handshake failed';
                    break;
            }
            
            updateConnectionStatus(false, errorMessage);
            
            // Only attempt to reconnect if the page is visible
            if (document.visibilityState === 'visible') {
                reconnectAttempts++;
                const delay = Math.min(RECONNECT_DELAY * Math.pow(1.5, reconnectAttempts - 1), 30000); // Max 30 second delay
                console.log(`Attempting to reconnect in ${delay/1000} seconds (attempt ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})`);
                reconnectTimeout = setTimeout(connectWebSocket, delay);
            }
        };
    } catch (error) {
        console.error('Error creating WebSocket connection:', error);
        updateConnectionStatus(false, 'Failed to create connection');
        reconnectAttempts++;
        reconnectTimeout = setTimeout(connectWebSocket, RECONNECT_DELAY);
    }
}

// Handle WebSocket messages
function handleMessage(message) {
    switch (message.type) {
        case 'initial_state':
        case 'pipeline_update':
            updatePipeline(message.data);
            break;
        case 'node_details':
            nodeDetails[message.nodeId] = message.data;
            if (selectedNode === message.nodeId && activeTab === 'details') {
                updateDetailsTab();
            }
            break;
        case 'node_files':
            nodeFiles[message.nodeId] = message.data;
            if (selectedNode === message.nodeId && activeTab === 'files') {
                updateFilesTab();
            }
            break;
        case 'ping':
            ws.send(JSON.stringify({ type: 'pong' }));
            break;
    }
}

// Update pipeline visualization
function updatePipeline(data) {
    pipelineState = data;
    
    // Update task name if available
    const taskNameElement = document.getElementById('task-name');
    if (data.task_name) {
        taskNameElement.textContent = data.task_name;
        taskNameElement.style.display = 'block';
    } else {
        taskNameElement.style.display = 'none';
    }
    
    if (currentView === 'graph') {
        updateGraph();
    } else {
        updateCompactView();
    }
    updateStatusCounts();
}

// Add custom layout function
function customLayout(cy) {
    const nodes = cy.nodes();
    const edges = cy.edges();
    const width = cy.width();
    const height = cy.height();
    
    // Calculate node ranks based on edge relationships
    const nodeRanks = new Map();
    const inDegree = new Map();
    const outDegree = new Map();
    
    // Initialize degrees
    nodes.forEach(node => {
        inDegree.set(node.id(), 0);
        outDegree.set(node.id(), 0);
    });
    
    // Calculate in/out degrees
    edges.forEach(edge => {
        const source = edge.source().id();
        const target = edge.target().id();
        outDegree.set(source, outDegree.get(source) + 1);
        inDegree.set(target, inDegree.get(target) + 1);
    });
    
    // Find source nodes (nodes with no incoming edges)
    const sourceNodes = nodes.filter(node => inDegree.get(node.id()) === 0);
    
    // Assign ranks using BFS
    const visited = new Set();
    const queue = [];
    
    // Start with source nodes
    sourceNodes.forEach(node => {
        queue.push({ node: node, rank: 0 });
        visited.add(node.id());
    });
    
    while (queue.length > 0) {
        const { node, rank } = queue.shift();
        nodeRanks.set(node.id(), rank);
        
        // Process outgoing edges
        node.outgoers('edge').forEach(edge => {
            const target = edge.target();
            if (!visited.has(target.id())) {
                visited.add(target.id());
                queue.push({ node: target, rank: rank + 1 });
            }
        });
    }
    
    // Group nodes by rank
    const rankGroups = new Map();
    nodeRanks.forEach((rank, nodeId) => {
        if (!rankGroups.has(rank)) {
            rankGroups.set(rank, []);
        }
        rankGroups.get(rank).push(cy.getElementById(nodeId));
    });
    
    // Calculate layout parameters
    const maxNodesPerRank = Math.max(...Array.from(rankGroups.values()).map(nodes => nodes.length));
    const numRanks = rankGroups.size;
    
    // Calculate spacing
    const nodeWidth = 200;
    const nodeHeight = 100;
    const horizontalSpacing = (width - nodeWidth) / (maxNodesPerRank - 1 || 1);
    const verticalSpacing = (height - nodeHeight) / (numRanks - 1 || 1);
    
    // Position nodes
    rankGroups.forEach((rankNodes, rank) => {
        // Sort nodes within rank by their out-degree (more outgoing edges go higher)
        rankNodes.sort((a, b) => outDegree.get(b.id()) - outDegree.get(a.id()));
        
        rankNodes.forEach((node, index) => {
            const x = index * horizontalSpacing;
            const y = rank * verticalSpacing;
            
            node.position({
                x: x,
                y: y
            });
        });
    });
}

// Update graph view
function updateGraph() {
    if (!cy || !pipelineState) return;

    // Store current viewport state
    const currentZoom = cy.zoom();
    const currentPan = cy.pan();
    
    // Get existing elements
    const existingNodes = new Map();
    const existingEdges = new Map();
    
    cy.nodes().forEach(node => {
        existingNodes.set(node.id(), node);
    });
    
    cy.edges().forEach(edge => {
        existingEdges.set(edge.id(), edge);
    });

    // Prepare new elements
    const newNodes = new Map();
    const newEdges = new Map();
    
    // Add nodes
    pipelineState.nodes.forEach(node => {
        const nodeData = {
            id: node.id,
            label: `${node.name}\n🔄 ${node.stats.live} | ✓ ${node.stats.success} | ✗ ${node.stats.failed}`,
            color: getNodeColor(node.status),
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
        // Use dagre layout for proper separation and no overlap
        cy.layout({
            name: 'dagre',
            rankDir: 'LR',
            nodeSep: 20,
            rankSep: 450,
            edgeSep: 10,
            ranker: 'network-simplex',
            padding: 50,
            animate: true,
            animationDuration: 500,
            fit: false
        }).run();
    }

    // Initial fit only once
    if (!hasFitOnce) {
        hasFitOnce = true;
        // Enable the fit button if it exists
        const fitButton = document.querySelector('.zoom-controls button:last-child');
        if (fitButton) {
            fitButton.disabled = false;
            // Trigger the reset button click after a short delay
            setTimeout(() => {
                fitButton.click();
            }, 500);
        }
    }

    // Restore viewport state (if not initial fit)
    if (hasFitOnce) {
        cy.zoom(currentZoom);
        cy.pan(currentPan);
    }

    // Update fish animations
    updateFishAnimations();
}

// Update compact view
function updateCompactView() {
    if (!pipelineState) return;

    const grid = document.getElementById('status-grid');
    const grouped = groupNodesByStatus(pipelineState.nodes);
    
    // Add search box
    let searchBox = document.getElementById('compact-search');
    if (!searchBox) {
        searchBox = document.createElement('input');
        searchBox.id = 'compact-search';
        searchBox.type = 'text';
        searchBox.placeholder = 'Search nodes...';
        searchBox.style.margin = '1rem 0';
        searchBox.style.width = '100%';
        searchBox.addEventListener('input', function() {
            compactSearch = this.value.toLowerCase();
            updateCompactView();
        });
        grid.parentNode.insertBefore(searchBox, grid);
    }

    grid.innerHTML = '';
    Object.entries(grouped).forEach(([status, nodes]) => {
        // Filter nodes by search
        let filteredNodes = nodes;
        if (compactSearch) {
            filteredNodes = nodes.filter(node => node.name.toLowerCase().includes(compactSearch));
        }
        const card = document.createElement('div');
        card.className = `status-card ${status}`;
        card.innerHTML = `
            <h3 style="color: ${getNodeColor(status)}; margin-bottom: 1rem;">
                ${status.toUpperCase()} (${filteredNodes.length})
            </h3>
        `;
        // Expand/collapse logic
        let showAll = expandedGroups[status];
        let displayNodes = filteredNodes;
        if (filteredNodes.length > 10 && !showAll) {
            displayNodes = filteredNodes.slice(0, 10);
        }
        displayNodes.forEach(node => {
            const nodeItem = document.createElement('div');
            nodeItem.className = 'node-item';
            nodeItem.innerHTML = `
                <div style="font-weight: bold; margin-bottom: 0.5rem;">${node.name}</div>
                <div style="font-size: 0.875rem; color: var(--text-secondary);">
                    🔄 ${node.stats.live} | ✓ ${node.stats.success} | ✗ ${node.stats.failed}
                </div>
            `;
            nodeItem.onclick = () => {
                selectedNode = node.id;
                showNodeDetails(node.id);
            };
            card.appendChild(nodeItem);
        });
        if (filteredNodes.length > 10) {
            const toggleBtn = document.createElement('button');
            toggleBtn.textContent = showAll ? 'Show less' : `Show more (${filteredNodes.length - 10} more)`;
            toggleBtn.style.marginTop = '1rem';
            toggleBtn.onclick = () => {
                expandedGroups[status] = !showAll;
                updateCompactView();
            };
            card.appendChild(toggleBtn);
        }
        grid.appendChild(card);
    });
}

// Fish animation
function updateFishAnimations() {
    if (!cy || !pipelineState) return;

    
    // Get current active edges and deduplicate them
    const activeEdges = new Set(pipelineState.edges
        .filter(edge => edge.active)
        .map(edge => `${edge.source}-${edge.target}`));
    
    // Store current fish positions before cleanup
    const currentPositions = new Map();
    fishAnimations.forEach((fish, edgeId) => {
        if (fish.element && fish.element.parentNode) {
            currentPositions.set(edgeId, {
                progress: fish.progress,
                element: fish.element
            });
        }
    });

    // First, remove all existing fish elements from the DOM
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
        // Remove all fish elements
        const existingFish = mainContent.querySelectorAll('.fish');
        existingFish.forEach(fish => {
            if (fish.parentNode) {
                fish.parentNode.removeChild(fish);
            }
        });

        // Double-check for any remaining fish elements
        const remainingFish = mainContent.querySelectorAll('.fish');
        if (remainingFish.length > 0) {
            console.warn(`Found ${remainingFish.length} remaining fish elements, removing them`);
            remainingFish.forEach(fish => {
                if (fish.parentNode) {
                    fish.parentNode.removeChild(fish);
                }
            });
        }
    }

    // Clear all animations and progress
    fishAnimations.clear();
    fishProgress.clear();

    // Cancel any existing animation frame
    if (animationFrame) {
        cancelAnimationFrame(animationFrame);
        animationFrame = null;
    }

    // Wait for the next frame to ensure nodes are positioned
    requestAnimationFrame(() => {
        // Create fish for active edges
        const createdFish = [];
        pipelineState.edges
            .filter(edge => edge.active)
            .forEach(edge => {
                const edgeId = `${edge.source}-${edge.target}`;
                // Skip if we've already created a fish for this edge
                if (createdFish.includes(edgeId)) {
                    return;
                }
                
                const sourceNode = cy.getElementById(edge.source);
                const targetNode = cy.getElementById(edge.target);
                
                // Only create fish if both nodes exist and are visible
                if (sourceNode && targetNode && 
                    sourceNode.visible() && targetNode.visible() &&
                    sourceNode.renderedPosition() && targetNode.renderedPosition()) {
                    
                    // Get progress from old fish if it exists
                    const oldFish = currentPositions.get(edgeId);
                    createFish(edge, oldFish?.progress);
                    createdFish.push(edgeId);
                }
            });


        // Start animation loop
        if (animationFrame) cancelAnimationFrame(animationFrame);
        animateFish();
    });
}

function createFish(edge, savedProgress) {
    const sourceNode = cy.getElementById(edge.source);
    const targetNode = cy.getElementById(edge.target);
    
    if (!sourceNode || !targetNode) {
        console.warn(`Cannot create fish: nodes not found for edge ${edge.source}-${edge.target}`);
        return;
    }

    const sourcePos = sourceNode.renderedPosition();
    const targetPos = targetNode.renderedPosition();
    
    if (!sourcePos || !targetPos) {
        console.warn(`Cannot create fish: positions not found for edge ${edge.source}-${edge.target}`);
        return;
    }

    const fish = document.createElement('div');
    fish.className = 'fish';
    fish.innerHTML = `<img src="/static/Artiphishell_black.svg" alt="fish" />`;
    
    // Use provided progress or start from source
    const edgeId = `${edge.source}-${edge.target}`;
    const progress = savedProgress !== undefined ? savedProgress : 0;
    
    // Set initial position based on progress
    const x = sourcePos.x + (targetPos.x - sourcePos.x) * progress;
    const y = sourcePos.y + (targetPos.y - sourcePos.y) * progress;
    const angle = Math.atan2(targetPos.y - sourcePos.y, targetPos.x - sourcePos.x);
    
    // Calculate size based on zoom level - now fish get bigger when zooming in
    const baseSize = 100; // Base size in pixels
    const zoom = cy.zoom();
    const scaledSize = baseSize * zoom; // Multiply by zoom instead of dividing
    
    fish.style.width = `${scaledSize}px`;
    fish.style.height = `${scaledSize}px`;
    fish.style.transform = `translate(${x - scaledSize/2}px, ${y - scaledSize/2}px) rotate(${angle}rad)`;
    
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
        mainContent.appendChild(fish);
        
        fishAnimations.set(edgeId, {
            element: fish,
            edge: edge,
            progress: progress,
            speed: 0.1 + Math.random() * 0.03,
            lastUpdate: Date.now(),
            baseSize: baseSize // Store base size for future updates
        });
    }
}

function animateFish() {
    const now = Date.now();
    const mainContent = document.querySelector('.main-content');
    const zoom = cy.zoom();
    
    if (!mainContent) {
        if (animationFrame) {
            cancelAnimationFrame(animationFrame);
            animationFrame = null;
        }
        return;
    }

    fishAnimations.forEach((fish, edgeId) => {
        const sourceNode = cy.getElementById(fish.edge.source);
        const targetNode = cy.getElementById(fish.edge.target);
        
        if (!sourceNode || !targetNode || 
            !sourceNode.visible() || !targetNode.visible() ||
            !sourceNode.renderedPosition() || !targetNode.renderedPosition() ||
            !fish.element || !fish.element.parentNode) {
            // Remove fish if nodes no longer exist or are not visible
            if (fish.element && fish.element.parentNode) {
                fish.element.parentNode.removeChild(fish.element);
            }
            fishAnimations.delete(edgeId);
            fishProgress.delete(edgeId);
            return;
        }

        // Calculate time-based progress to ensure smooth animation
        const timeDelta = (now - fish.lastUpdate) / 1000; // Convert to seconds
        fish.progress = (fish.progress + fish.speed * timeDelta) % 1;
        fish.lastUpdate = now;
        
        // Save progress for next update
        fishProgress.set(edgeId, fish.progress);

        const sourcePos = sourceNode.renderedPosition();
        const targetPos = targetNode.renderedPosition();
        
        const x = sourcePos.x + (targetPos.x - sourcePos.x) * fish.progress;
        const y = sourcePos.y + (targetPos.y - sourcePos.y) * fish.progress;
        
        const angle = Math.atan2(targetPos.y - sourcePos.y, targetPos.x - sourcePos.x);
        
        // Update size based on current zoom - now fish get bigger when zooming in
        const scaledSize = fish.baseSize * zoom; // Multiply by zoom instead of dividing
        fish.element.style.width = `${scaledSize}px`;
        fish.element.style.height = `${scaledSize}px`;
        
        fish.element.style.transform = `translate(${x - scaledSize/2}px, ${y - scaledSize/2}px) rotate(${angle}rad)`;
    });

    animationFrame = requestAnimationFrame(animateFish);
}

// Helper functions
function getNodeColor(status) {
    const colors = {
        running: '#2ecc71',
        success: '#3498db',
        failed: '#e74c3c',
        pending: '#95a5a6',
        mixed: '#9b59b6'
    };
    return colors[status] || colors.pending;
}

function updateStatusCounts() {
    if (!pipelineState) return;
    
    const counts = {
        running: 0,
        success: 0,
        failed: 0,
        mixed: 0,
        pending: 0
    };
    
    pipelineState.nodes.forEach(node => {
        counts[node.status]++;
    });
    
    document.getElementById('running-count').textContent = counts.running;
    document.getElementById('success-count').textContent = counts.success;
    document.getElementById('failed-count').textContent = counts.failed;
    document.getElementById('mixed-count').textContent = counts.mixed;
    document.getElementById('pending-count').textContent = counts.pending;
}

function groupNodesByStatus(nodes) {
    return nodes.reduce((acc, node) => {
        if (!acc[node.status]) acc[node.status] = [];
        acc[node.status].push(node);
        return acc;
    }, {});
}

// UI functions
function switchView(view) {
    currentView = view;
    document.querySelectorAll('.view-toggle button').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    // Clean up fish animations when switching views
    cleanupFishAnimations();
    
    if (view === 'graph') {
        document.getElementById('cy').style.display = 'block';
        document.querySelector('.compact-view').style.display = 'none';
        document.querySelector('.status-box').style.display = 'block';
        updateGraph();
    } else {
        document.getElementById('cy').style.display = 'none';
        document.querySelector('.compact-view').style.display = 'block';
        document.querySelector('.status-box').style.display = 'none';
        updateCompactView();
    }
}

function toggleTheme() {
    const body = document.body;
    const currentTheme = body.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    body.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
}

function resetServer() {
    fetch('/restart', { method: 'GET' }).catch(() => {
        // Ignore any errors since we don't care about the response
    });
}

function showNodeDetails(nodeId) {
    document.getElementById('node-details').classList.add('open');
    document.getElementById('node-title').textContent = nodeId;
    
    // Request details from server
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'request_node_details', nodeId }));
        ws.send(JSON.stringify({ type: 'request_node_files', nodeId }));
    }
    
    // Update all tabs immediately with available data
    updateDetailsTab();
    updateFilesTab();
    updateLogsTab();
    updateConnectionsTab();
}

function closeDetails() {
    document.getElementById('node-details').classList.remove('open');
    selectedNode = null;
    if (cy) cy.$(':selected').unselect();
}

function switchTab(tab) {
    activeTab = tab;
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');
    
    switch (tab) {
        case 'details':
            updateDetailsTab();
            break;
        case 'connections':
            updateConnectionsTab();
            break;
    }
}

function updateDetailsTab() {
    const content = document.getElementById('details-content');
    const details = nodeDetails[selectedNode];
    
    if (!details) {
        content.innerHTML = '<p>Loading details...</p>';
        return;
    }
    
    content.innerHTML = `
        <div style="margin-bottom: 2rem;">
            <h3>Repositories</h3>
            ${Object.entries(details.repositories || {}).map(([name, info]) => 
                !name.startsWith('INHIBITION') ? `
                <div class="repo-container" style="margin: 0.5rem 0;">
                    <div class="repo-header" onclick="toggleRepoFiles('${selectedNode}', '${name}')" style="padding: 0.5rem; background: var(--bg-primary); border-radius: 4px; cursor: pointer; display: flex; justify-content: space-between; align-items: center;">
                        <strong>${name}</strong>
                        <span class="repo-count">(${info.count} items)</span>
                        <span class="repo-arrow">▼</span>
                    </div>
                    <div id="repo-files-${selectedNode}-${name}" class="repo-files" style="display: none; margin-top: 0.5rem; padding: 0.5rem; background: var(--bg-secondary); border-radius: 4px;">
                        <div class="loading-files"></div>
                    </div>
                </div>
            ` : ''
            ).join('')}
        </div>
        
        <div style="margin-bottom: 2rem;">
            <h3>Metrics</h3>
            ${details.metrics ? `
                <div>Avg Processing Time: ${details.metrics.avg_processing_time}s</div>
                <div>Throughput: ${details.metrics.throughput}</div>
                <div>Error Rate: ${(details.metrics.error_rate * 100).toFixed(2)}%</div>
                <div>Last Run: ${new Date(details.metrics.last_run).toLocaleString()}</div>
            ` : 'No metrics available'}
        </div>
    `;
}

async function toggleRepoFiles(nodeId, repoName) {
    const filesContainer = document.getElementById(`repo-files-${nodeId}-${repoName}`);
    const arrow = filesContainer.previousElementSibling.querySelector('.repo-arrow');
    
    if (filesContainer.style.display === 'none') {
        filesContainer.style.display = 'block';
        arrow.textContent = '▲';
        
        // Add search input if it doesn't exist
        if (!filesContainer.querySelector('.repo-search')) {
            const searchDiv = document.createElement('div');
            searchDiv.className = 'repo-search';
            searchDiv.innerHTML = `
                <input type="text" 
                       placeholder="Search files..." 
                       class="repo-search-input"
                       onkeyup="filterRepoFiles('${nodeId}', '${repoName}', this.value)">
            `;
            filesContainer.insertBefore(searchDiv, filesContainer.firstChild);
        }

        // Show loading state only during initial load
        const filesList = document.createElement('div');
        filesList.className = 'files-list';
        filesList.innerHTML = '<div class="loading-files">Loading files...</div>';
        filesContainer.appendChild(filesList);
        
        // Request files from server
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'request_node_files', nodeId }));
        }
        
        // Wait for files to be loaded
        const files = await new Promise(resolve => {
            const checkFiles = () => {
                if (nodeFiles[nodeId]) {
                    resolve(nodeFiles[nodeId].filter(f => f.repo === repoName));
                } else {
                    setTimeout(checkFiles, 100);
                }
            };
            checkFiles();
        });
        
        // Initialize or update the filter
        repoFileFilters[`${nodeId}-${repoName}`] = '';
        
        // Display files
        updateRepoFilesDisplay(nodeId, repoName, files);
    } else {
        filesContainer.style.display = 'none';
        arrow.textContent = '▼';
    }
}

// Add new function to filter files
function filterRepoFiles(nodeId, repoName, searchTerm) {
    repoFileFilters[`${nodeId}-${repoName}`] = searchTerm.toLowerCase();
    const files = nodeFiles[nodeId].filter(f => f.repo === repoName);
    updateRepoFilesDisplay(nodeId, repoName, files);
}

// Update the updateRepoFilesDisplay function to handle loading state
function updateRepoFilesDisplay(nodeId, repoName, files) {
    const filesContainer = document.getElementById(`repo-files-${nodeId}-${repoName}`);
    const searchTerm = repoFileFilters[`${nodeId}-${repoName}`] || '';
    
    // Filter files based on search term
    const filteredFiles = files.filter(file => 
        file.name.toLowerCase().includes(searchTerm)
    );
    
    // Update the files display
    const filesList = filesContainer.querySelector('.files-list') || document.createElement('div');
    filesList.className = 'files-list';
    
    if (filteredFiles.length === 0) {
        filesList.innerHTML = '<div class="no-files">No matching files found</div>';
    } else {
        filesList.innerHTML = filteredFiles.map(file => `
            <div class="file-item">
                <div class="file-info">
                    <div class="file-name">${file.name}</div>
                    <div class="file-meta">
                        ${formatFileSize(file.size)}
                    </div>
                </div>
                <div class="file-actions">
                    <button class="action-button view-button" onclick="viewFile('${nodeId}', '${repoName}', '${file.path}')">
                        <span class="button-icon">👁️</span>
                        <span class="button-text">View</span>
                    </button>
                    <button class="action-button download-button" onclick="downloadFile('${nodeId}', '${repoName}', '${file.path}')">
                        <span class="button-icon">⬇️</span>
                        <span class="button-text">Download</span>
                    </button>
                </div>
            </div>
        `).join('');
    }
    
    // Replace the old files list with the new one
    const oldFilesList = filesContainer.querySelector('.files-list');
    if (oldFilesList) {
        filesContainer.replaceChild(filesList, oldFilesList);
    } else {
        filesContainer.appendChild(filesList);
    }
}

async function viewFile(nodeId, repoName, filepath) {
    try {
        const response = await fetch(`/api/nodes/${nodeId}/files/${repoName}/${filepath}`);
        if (!response.ok) throw new Error('Failed to fetch file');
        
        const content = await response.text();
        
        // Create modal for viewing file content
        const modal = document.createElement('div');
        modal.className = 'file-view-modal';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>${filepath.split('/').pop()}</h3>
                    <button class="close-button" onclick="event.stopPropagation(); this.closest('.file-view-modal').remove()">×</button>
                </div>
                <div class="modal-body">
                    <pre class="file-content">${escapeHtml(content)}</pre>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Add click outside to close
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                e.stopPropagation();
                modal.remove();
            }
        });

        // Prevent clicks inside modal from closing it
        modal.querySelector('.modal-content').addEventListener('click', (e) => {
            e.stopPropagation();
        });
    } catch (error) {
        console.error('Error viewing file:', error);
        alert('Failed to view file content');
    }
}

// Helper function to escape HTML special characters
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function updateFilesTab() {
    const content = document.getElementById('details-content');
    const files = nodeFiles[selectedNode];
    
    if (!files) {
        content.innerHTML = '<p>Loading files...</p>';
        return;
    }
    
    content.innerHTML = `
        <div>
            ${files.map(file => `
                <div style="margin: 0.5rem 0; padding: 1rem; background: var(--bg-primary); border-radius: 4px; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-weight: bold;">${file.name}</div>
                        <div style="font-size: 0.875rem; color: var(--text-secondary);">
                            ${file.repo} • ${formatFileSize(file.size)}
                        </div>
                    </div>
                    <button onclick="downloadFile('${selectedNode}', '${file.repo}', '${file.path}')" style="background: var(--status-success); color: white;">
                        Download
                    </button>
                </div>
            `).join('')}
        </div>
    `;
}

function updateLogsTab() {
    const content = document.getElementById('details-content');
    const details = nodeDetails[selectedNode];
    
    if (!details || !details.logs) {
        content.innerHTML = '<p>No logs available</p>';
        return;
    }
    
    content.innerHTML = `
        <div style="font-family: monospace; font-size: 0.875rem;">
            ${details.logs.map(log => `
                <div style="margin: 0.25rem 0; padding: 0.5rem; background: var(--bg-primary); border-radius: 4px;">
                    <span style="color: var(--text-secondary);">${log.timestamp}</span>
                    <span style="color: ${log.level === 'ERROR' ? 'var(--status-failed)' : 'var(--status-success)'};">[${log.level}]</span>
                    ${log.message}
                </div>
            `).join('')}
        </div>
    `;
}

function updateConnectionsTab() {
    const content = document.getElementById('details-content');
    if (!pipelineState || !selectedNode) {
        content.innerHTML = '<p>No connection data available</p>';
        return;
    }

    // Find incoming and outgoing edges
    const incomingEdges = pipelineState.edges.filter(edge => edge.target === selectedNode);
    const outgoingEdges = pipelineState.edges.filter(edge => edge.source === selectedNode);

    // Get unique source and target nodes
    const incomingNodes = [...new Set(incomingEdges.map(edge => edge.source))];
    const outgoingNodes = [...new Set(outgoingEdges.map(edge => edge.target))];

    // Get node info for each connected node
    const incomingNodeInfo = incomingNodes.map(id => pipelineState.nodes.find(node => node.id === id));
    const outgoingNodeInfo = outgoingNodes.map(id => pipelineState.nodes.find(node => node.id === id));

    // Sort nodes by status priority and then alphabetically
    const statusPriority = {
        'running': 0,
        'failed': 1,
        'mixed': 2,
        'success': 3,
        'pending': 4
    };

    function sortNodes(nodes) {
        return nodes.sort((a, b) => {
            // First sort by status
            const statusDiff = statusPriority[a.status] - statusPriority[b.status];
            if (statusDiff !== 0) return statusDiff;
            // Then sort alphabetically by name
            return a.name.localeCompare(b.name);
        });
    }

    const sortedIncomingNodes = sortNodes(incomingNodeInfo);
    const sortedOutgoingNodes = sortNodes(outgoingNodeInfo);

    // Store the current search terms
    const currentIncomingFilter = connectionFilters.incoming;
    const currentOutgoingFilter = connectionFilters.outgoing;

    content.innerHTML = `
        <div class="connections-section">
            <div class="connection-group">
                <div class="connection-header">
                    <h3>Incoming Nodes</h3>
                    <div class="connection-search">
                        <input type="text" 
                               placeholder="Search incoming nodes..." 
                               class="connection-search-input"
                               onkeyup="filterConnections('incoming', this.value)"
                               value="${currentIncomingFilter}">
                    </div>
                </div>
                <div class="connection-group-content" id="incoming-connections">
                    ${filterAndDisplayConnections(sortedIncomingNodes, 'incoming')}
                </div>
            </div>

            <div class="connection-group">
                <div class="connection-header">
                    <h3>Outgoing Nodes</h3>
                    <div class="connection-search">
                        <input type="text" 
                               placeholder="Search outgoing nodes..." 
                               class="connection-search-input"
                               onkeyup="filterConnections('outgoing', this.value)"
                               value="${currentOutgoingFilter}">
                    </div>
                </div>
                <div class="connection-group-content" id="outgoing-connections">
                    ${filterAndDisplayConnections(sortedOutgoingNodes, 'outgoing')}
                </div>
            </div>
        </div>
    `;
}

function filterConnections(type, searchTerm) {
    connectionFilters[type] = searchTerm.toLowerCase();
    
    // Get the current node lists
    const incomingEdges = pipelineState.edges.filter(edge => edge.target === selectedNode);
    const outgoingEdges = pipelineState.edges.filter(edge => edge.source === selectedNode);
    const incomingNodes = [...new Set(incomingEdges.map(edge => edge.source))];
    const outgoingNodes = [...new Set(outgoingEdges.map(edge => edge.target))];
    const incomingNodeInfo = incomingNodes.map(id => pipelineState.nodes.find(node => node.id === id));
    const outgoingNodeInfo = outgoingNodes.map(id => pipelineState.nodes.find(node => node.id === id));

    // Sort nodes
    const statusPriority = {
        'running': 0,
        'failed': 1,
        'mixed': 2,
        'success': 3,
        'pending': 4
    };

    function sortNodes(nodes) {
        return nodes.sort((a, b) => {
            const statusDiff = statusPriority[a.status] - statusPriority[b.status];
            if (statusDiff !== 0) return statusDiff;
            return a.name.localeCompare(b.name);
        });
    }

    const sortedIncomingNodes = sortNodes(incomingNodeInfo);
    const sortedOutgoingNodes = sortNodes(outgoingNodeInfo);

    // Update only the content of the respective connection group
    if (type === 'incoming') {
        const content = document.getElementById('incoming-connections');
        if (content) {
            content.innerHTML = filterAndDisplayConnections(sortedIncomingNodes, 'incoming');
        }
    } else {
        const content = document.getElementById('outgoing-connections');
        if (content) {
            content.innerHTML = filterAndDisplayConnections(sortedOutgoingNodes, 'outgoing');
        }
    }
}

function filterAndDisplayConnections(nodes, type) {
    const searchTerm = connectionFilters[type] || '';
    const filteredNodes = nodes.filter(node => 
        node.name.toLowerCase().includes(searchTerm)
    );

    if (filteredNodes.length === 0) {
        return '<p>No matching nodes found</p>';
    }

    return filteredNodes.map(node => `
        <div class="connection-item" onclick="navigateToNode('${node.id}')">
            <div class="connection-dot ${node.status}"></div>
            <div class="connection-info">
                <div class="connection-name">${node.name}</div>
                <div class="connection-stats">
                    🔄 ${node.stats.live} | ✓ ${node.stats.success} | ✗ ${node.stats.failed}
                </div>
            </div>
        </div>
    `).join('');
}

function navigateToNode(nodeId) {
    selectedNode = nodeId;
    showNodeDetails(nodeId);
    
    // Zoom to the node with less zoom
    const node = cy.getElementById(nodeId);
    if (node) {
        cy.animate({
            fit: {
                eles: node,
                padding: cyto_zoom_fit_padding
            },
            duration: 500
        });
    }
}

async function downloadFile(nodeId, repo, filepath) {
    try {
        const response = await fetch(`http://localhost:8000/api/nodes/${nodeId}/files/${repo}/${filepath}`);
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filepath.split('/').pop();
        a.click();
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Download failed:', error);
    }
}

// Update connection status with more detailed information
function updateConnectionStatus(connected, message = '') {
    const statusDot = document.querySelector('.connection-dot');
    const statusText = document.querySelector('.connection-text');

    if (connected) {
        statusDot.classList.add('connected');
        statusText.textContent = 'Connected';
    } else {
        statusDot.classList.remove('connected');
        statusText.textContent = message || 'Disconnected';
    }
}

// Add event listener for closing node details when clicking outside
function setupNodeDetailsClose() {
    document.addEventListener('mousedown', function(event) {
        const details = document.getElementById('node-details');
        const modal = document.querySelector('.file-view-modal');
        
        // Don't close if clicking inside modal
        if (modal && (modal.contains(event.target) || event.target === modal)) {
            return;
        }
        
        if (details && details.classList.contains('open')) {
            if (!details.contains(event.target)) {
                closeDetails();
            }
        }
    });
}

// Add ESC key handler
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        // Check if there's an open modal
        const openModal = document.querySelector('.file-view-modal');
        if (openModal) {
            // If modal is open, close it and stop event propagation
            event.stopPropagation();
            openModal.remove();
        } else if (selectedNode) {
            // If no modal but sidebar is open, close the sidebar
            closeDetails();
        }
    }
});

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Create container if it doesn't exist
    if (!document.getElementById('cy')) {
        const container = document.createElement('div');
        container.id = 'cy';
        document.body.appendChild(container);
    }

    initCytoscape();
    connectWebSocket();
    setupNodeDetailsClose();

});

// Cleanup on unload
window.addEventListener('beforeunload', () => {
    if (ws) ws.close();
    if (animationFrame) cancelAnimationFrame(animationFrame);
});

// Set initial theme
document.documentElement.setAttribute('data-theme', theme);

// Add new cleanup function
function cleanupFishAnimations() {
    // Remove all fish elements from the DOM
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
        const existingFish = mainContent.querySelectorAll('.fish');
        existingFish.forEach(fish => {
            if (fish.parentNode) {
                fish.parentNode.removeChild(fish);
            }
        });
    }
    
    // Clear animation data
    fishAnimations.clear();
    fishProgress.clear();
    
    // Cancel any existing animation frame
    if (animationFrame) {
        cancelAnimationFrame(animationFrame);
        animationFrame = null;
    }
}

// Helper function to format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Add visibility change handler to manage reconnection
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
        // If we're disconnected, try to reconnect when the page becomes visible
        if (!ws || ws.readyState === WebSocket.CLOSED) {
            reconnectAttempts = 0; // Reset attempts when page becomes visible
            connectWebSocket();
        }
    }
});