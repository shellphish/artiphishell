// UI Components
import { formatFileSize, viewFile, downloadFile, viewLivePodLogs } from '../utils/file.js';
import { deleteDoneRepo, deleteDoneRepoItem, confirmDelete, showDeleteSuccess, showDeleteError } from '../utils/delete.js';
import { NodeInfo, FileInfo } from '../core/models.js';

/** @type {Object<string, NodeInfo>} */
export let nodeDetails = {};
/** @type {Object<string, FileInfo[]>} */
export let nodeFiles = {};
export let activeTab = 'details';
/** @type {string|null} */
export let selectedNode = null;
let currentView = 'graph';
let connectionFilters = {
    incoming: '',
    outgoing: ''
};
/** @type {Object<string, boolean>} */
export let nodeDetailsLoading = {};

// Add copyToClipboard function at the top with other utility functions
async function copyToClipboard(text) {
    // Try using the modern Async Clipboard API first
    if (navigator.clipboard && window.isSecureContext) {
        try {
            await navigator.clipboard.writeText(text);
            return;
        } catch (err) {
            console.warn('Async Clipboard API failed, falling back to execCommand');
        }
    }
    
    // Fallback for non-secure contexts or when Async Clipboard API fails
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    
    try {
        document.execCommand('copy');
    } catch (err) {
        console.error('Failed to copy text: ', err);
    }
    
    document.body.removeChild(textarea);
}

// Make copyToClipboard available globally
window.copyToClipboard = copyToClipboard;

// Make toggleRepoFiles available globally
/**
 * Toggles the visibility of repository files for a specific node
 * @param {string} nodeId - The ID of the node
 * @param {string} repoName - The name of the repository
 */
window.toggleRepoFiles = function(nodeId, repoName) {
    const filesContainer = document.getElementById(`repo-files-${nodeId}-${repoName}`);
    if (!filesContainer) return;

    const isExpanded = filesContainer.style.display !== 'none';
    filesContainer.style.display = isExpanded ? 'none' : 'block';
    
    // Update arrow
    const arrow = filesContainer.previousElementSibling.querySelector('.repo-arrow');
    if (arrow) {
        arrow.textContent = isExpanded ? '▼' : '▲';
    }

    if (isExpanded || filesContainer.children.length > 0)
        return;

    // If expanding, load files if not already loaded
    const files = nodeFiles[nodeId];
    if (!files) {
        const event = new CustomEvent('requestNodeFiles', { detail: { nodeId } });
        document.dispatchEvent(event);
        return;
    }

    const repoFiles = files.filter(file => file.repo === repoName);
    if (repoFiles.length === 0) {
        filesContainer.innerHTML = '<div class="no-files">No files found in this repository</div>';
        return;
    }

    // Debug: Log failure type information for failed_logs
    if (repoName === 'failed_logs' || repoName === 'logs') {
        console.log(`[FAILURE_TYPE_FRONTEND] Rendering ${repoName} with ${repoFiles.length} files`);
        repoFiles.forEach(file => {
            console.log(`[FAILURE_TYPE_FRONTEND] File ${file.name}: failure_type=${file.failure_type}, repo=${file.repo}`);
            if (file.failure_type) {
                console.log(`[FAILURE_TYPE_FRONTEND] File ${file.name} has failure type: ${file.failure_type}`);
            }
        });
    }

    filesContainer.innerHTML = `
        <div class="repo-search">
            <input type="text" 
                    class="repo-search-input" 
                    placeholder="Search files..." 
                    onkeyup="filterRepoFiles('${nodeId}', '${repoName}', this.value)">
        </div>
        <div class="files-list" id="files-list-${nodeId}-${repoName}">
            ${repoFiles.map(file => `
                <div class="file-item" data-filename="${file.name.toLowerCase()}">
                    <div class="file-info">
                        <div class="file-name" onclick="copyToClipboard('${file.name}')">
                            ${file.name}
                        </div>
                        <div class="file-meta">
                            <div class="file-actions">
                                <span class="file-size">${repoName === 'live' ? 'Live Job' : formatFileSize(file.size)}</span>
                                ${repoName === 'live' ? `
                                    <button class="action-button view-button" onclick="window.viewLivePodLogs('${nodeId}', '${file.path}')">
                                        <span class="button-icon">📋</span> View Logs
                                    </button>
                                ` : `
                                    <button class="action-button view-button" onclick="window.viewFile('${nodeId}', '${file.repo}', '${file.path}')">
                                        <span class="button-icon">👁️</span> View
                                    </button>
                                    <button class="action-button download-button" onclick="window.downloadFile('${nodeId}', '${file.repo}', '${file.path}')">
                                        <span class="button-icon">⬇️</span> Download
                                    </button>
                                `}
                            </div>
                        </div>
                        ${(() => {
                            const shouldShowTag = (repoName === 'failed_logs' || repoName === 'logs') && file.failure_type;
                            console.log(`[TEMPLATE_DEBUG] File ${file.name}: repoName=${repoName}, failure_type=${file.failure_type}, shouldShowTag=${shouldShowTag}`);
                            return shouldShowTag ? `
                                <div class="file-failure-type">
                                    <span class="failure-type-tag ${file.failure_type}">
                                        ${file.failure_type === 'timeout' ? 'TIMEOUT' : 
                                          file.failure_type === 'oomkilled' ? 'OOM' : 
                                          file.failure_type === 'other' ? 'FAILED' : 'UNKNOWN'}
                                    </span>
                                </div>
                            ` : '';
                        })()}
                    </div>
                    ${file.repo === 'done' ? `
                        <div class="file-delete-container">
                            <button class="delete-item-btn" onclick="deleteDoneRepoItem('${nodeId}', '${file.path}')" title="Delete this item from done repository">
                                🗑️
                            </button>
                        </div>
                    ` : ''}
                </div>
            `).join('')}
        </div>
    `;
};

// Add filterRepoFiles function to window object
window.filterRepoFiles = function(nodeId, repoName, searchTerm) {
    const filesList = document.getElementById(`files-list-${nodeId}-${repoName}`);
    if (!filesList) return;

    const searchLower = searchTerm.toLowerCase();
    const fileItems = filesList.querySelectorAll('.file-item');

    fileItems.forEach(item => {
        const fileName = item.dataset.filename;
        item.style.display = fileName.includes(searchLower) ? 'block' : 'none';
    });
};

// Make viewFile, downloadFile, and viewLivePodLogs available globally
window.viewFile = viewFile;
window.downloadFile = downloadFile;
window.viewLivePodLogs = viewLivePodLogs;



const nodeColors = {
    'running': '#4CAF50',  // Green
    'success': '#2196F3',  // Blue
    'failed': '#F44336',   // Red
    'mixed': '#9b59b6',    // Purple
    'pending': '#9E9E9E'   // Grey
};
// Helper function to get node color based on status
function getNodeColor(status) {
    return nodeColors[status] || '#9E9E9E';
}

export function showNodeDetails(nodeId) {
    selectedNode = nodeId;
 
    // Only update the currently active tab
    switch (activeTab) {
        case 'details':
            updateDetailsTab();
            break;
        case 'connections':
            updateConnectionsTab();
            break;
        case 'files':
            updateFilesTab();
            break;
    }

    const detailsPanel = document.getElementById('node-details');
    detailsPanel.classList.add('open');
    
    // Get node stats if available
    const details = nodeDetails[nodeId] || new NodeInfo({id: nodeId, stats: {live: 0, success: 0, failed: 0}});

    // Create a container for the title, stats, and button
    const titleContainer = document.getElementById('node-title').parentElement;
    titleContainer.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 0.5rem;">
            <h2 id="node-title" style="margin-bottom: 0.25rem;">${nodeId}</h2>
            <div class="node-stats-badges">
                <span class="badge badge-running${details.stats.live === 0 ? ' badge-inactive' : ''}">Running: ${details.stats.live}</span>
                <span class="badge badge-success${details.stats.success === 0 ? ' badge-inactive' : ''}">Succeeded: ${details.stats.success}</span>
                <span class="badge badge-failed${details.stats.failed === 0 ? ' badge-inactive' : ''}">Failed: ${details.stats.failed}</span>
                ${(() => {
                    console.log('[BADGE_DEBUG] Detail view stats:', details.stats);
                    console.log('[BADGE_DEBUG] Timeout value:', details.stats.timeout, 'Type:', typeof details.stats.timeout);
                    console.log('[BADGE_DEBUG] OOMKilled value:', details.stats.oomkilled, 'Type:', typeof details.stats.oomkilled);
                    return '';
                })()}
                ${details.stats.timeout > 0 ? `<span class="badge badge-timeout">Timeout: ${details.stats.timeout}</span>` : ''}
                ${details.stats.oomkilled > 0 ? `<span class="badge badge-oomkilled">OOM: ${details.stats.oomkilled}</span>` : ''}
            </div>
            <button class="action-button" onclick="window.runWhyReady('${nodeId}')">
                <span class="button-icon">❓</span> Why Ready
            </button>
        </div>
    `;

    // Add close button to the details-header
    const detailsHeader = document.querySelector('.details-header');
    const closeButton = document.createElement('button');
    closeButton.className = 'close-details';
    closeButton.textContent = '×';
    closeButton.onclick = closeDetails;
    
    // Remove any existing close button
    const existingButton = detailsHeader.querySelector('.close-details');
    if (existingButton) {
        existingButton.remove();
    }
    
    detailsHeader.appendChild(closeButton);
    
    // Request details from server
    const event = new CustomEvent('requestNodeDetails', { detail: { nodeId } });
    document.dispatchEvent(event);
   
}

export function closeDetails() {
    document.getElementById('node-details').classList.remove('open');
    selectedNode = null;
    
    // Get Cytoscape instance and unselect nodes
    const event = new CustomEvent('getCytoscape');
    document.dispatchEvent(event);
    const cy = event.detail;
    if (cy && typeof cy.$ === 'function') {
        cy.$(':selected').unselect();
    }
    const searchContainer = document.querySelector('.graph-search-container');
    searchContainer.classList.remove('with-details');
}

export function switchTab(tab) {
    activeTab = tab;
    
    // Update tab buttons
    document.querySelectorAll('.tab').forEach(t => {
        t.classList.toggle('active', t.dataset.tab === tab);
    });
    
    // Update content based on tab
    switch (tab) {
        case 'details':
            updateDetailsTab();
            break;
        case 'connections':
            updateConnectionsTab();
            break;
    }
}

export function updateDetailsTab() {
    const content = document.getElementById('details-content');
    const details = nodeDetails[selectedNode];
    
    if (!details) {
        content.innerHTML = '<p>Loading details...</p>';
        return;
    }
    
    // Create a copy of repositories to avoid modifying the original
    let repositories = { ...details.repositories };
    
    // If we have logs, done, and success repos, create failed_logs
    if (details.stats.failed > 0) {
        const logsFiles = nodeFiles[selectedNode]?.filter(f => f.repo === 'logs') || [];
        const doneFiles = nodeFiles[selectedNode]?.filter(f => f.repo === 'done') || [];
        const successFiles = nodeFiles[selectedNode]?.filter(f => f.repo === 'success') || [];
        
        // Get filenames from each repo
        const doneFilenames = new Set(doneFiles.map(f => f.name));
        const successFilenames = new Set(successFiles.map(f => f.name));
        
        // Filter logs files that are in done but not in success
        const failedLogsFiles = logsFiles.filter(f => 
            doneFilenames.has(f.name) && !successFilenames.has(f.name)
        );
        
        // Add failed_logs to repositories if we found any files
        if (failedLogsFiles.length > 0) {
            // Create a new object with failed_logs at the top
            repositories = {
                failed_logs: {
                    count: failedLogsFiles.length
                },
                ...repositories
            };
            // Store the files in nodeFiles for later use
            if (!nodeFiles[selectedNode]) {
                nodeFiles[selectedNode] = [];
            }
            
            // Add failed log files with their failure type information (already provided by backend)
            const failedLogsWithRepo = failedLogsFiles.map(f => ({
                ...f,
                repo: 'failed_logs'
            }));
            
            // Debug: Log the failed logs files to see if failure_type is preserved
            console.log('[FAILED_LOGS_DEBUG] Failed logs files:', failedLogsWithRepo);
            failedLogsWithRepo.forEach(f => {
                if (f.failure_type) {
                    console.log(`[FAILED_LOGS_DEBUG] File ${f.name} has failure_type: ${f.failure_type}`);
                }
            });
            
            nodeFiles[selectedNode].push(...failedLogsWithRepo);
        }
    }

    
    content.innerHTML = `
        <div style="margin-bottom: 2rem;">
            <h3>Repositories</h3>
            ${Object.entries(repositories).map(([name, info]) => 
                !name.startsWith('INHIBITION') ? `
                <div class="repo-container" data-repo="${name}" style="margin: 0.5rem 0;">
                    <div class="repo-header" onclick="toggleRepoFiles('${selectedNode}', '${name}')" style="padding: 0.5rem; background: var(--bg-primary); border-radius: 4px; cursor: pointer; display: flex; justify-content: space-between; align-items: center;">
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <strong>${name}</strong>
                            ${name === 'done' ? `
                                <button class="delete-repo-btn" onclick="event.stopPropagation(); deleteDoneRepo('${selectedNode}')" title="Delete entire done repository">
                                    🗑️
                                </button>
                            ` : ''}
                        </div>
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <span class="repo-count">(${info.count} items)</span>
                            <span class="repo-arrow">▼</span>
                        </div>
                    </div>
                    <div id="repo-files-${selectedNode}-${name}" class="repo-files" style="display: none; margin-top: 0.5rem; padding: 0.5rem; background: var(--bg-secondary); border-radius: 4px;">
                    </div>
                </div>
            ` : ''
            ).join('')}
        </div>
    `;
}

export function updateFilesTab() {
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

export function updateConnectionsTab() {
    const content = document.getElementById('details-content');
    const event = new CustomEvent('getPipelineState');
    document.dispatchEvent(event);
    const pipelineState = event.detail;
    
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
        </div>
    `;
}

/**
 * Filters the connections for a given type and search term
 * @param {string} type - The type of connections to filter
 * @param {string} searchTerm - The search term to filter by
 */
export function filterConnections(type, searchTerm) {
    connectionFilters[type] = searchTerm.toLowerCase();
    
    // Get the current node lists
    const event = new CustomEvent('getPipelineState');
    document.dispatchEvent(event);
    const pipelineState = event.detail;
    
    /** @type {EdgeInfo[]} */
    const incomingEdges = pipelineState.edges.filter(edge => edge.target === selectedNode);
    /** @type {EdgeInfo[]} */
    const outgoingEdges = pipelineState.edges.filter(edge => edge.source === selectedNode);
    /** @type {string[]} */
    const incomingNodes = [...new Set(incomingEdges.map(edge => edge.source))];
    /** @type {string[]} */
    const outgoingNodes = [...new Set(outgoingEdges.map(edge => edge.target))];
    /** @type {NodeInfo[]} */
    const incomingNodeInfo = incomingNodes.map(id => pipelineState.nodes.find(node => node.id === id));
    /** @type {NodeInfo[]} */
    const outgoingNodeInfo = outgoingNodes.map(id => pipelineState.nodes.find(node => node.id === id));

    // Sort nodes
    const statusPriority = {
        'running': 0,
        'failed': 1,
        'mixed': 2,
        'success': 3,
        'pending': 4
    };

    /**
     * Sorts nodes by status and name
     * @param {NodeInfo[]} nodes - The nodes to sort
     * @returns {NodeInfo[]} The sorted nodes
     */
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

/**
 * Filters the connections for a given type and search term
 * @param {NodeInfo[]} nodes - The nodes to filter
 * @param {string} type - The type of connections to filter
 */
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

export function toggleTheme() {
    const body = document.body;
    const currentTheme = body.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    const themeButton = document.querySelector('.theme-toggle');
    
    // Update theme
    body.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    // Update button icon
    themeButton.innerHTML = newTheme === 'dark' ? '☀️' : '🌙';
    
    // Update Cytoscape background
    const event = new CustomEvent('getCytoscape');
    document.dispatchEvent(event);
    const cy = event.detail;
    
    if (cy) {
        cy.style()
            .selector('core')
            .style({
                'background-color': newTheme === 'dark' ? '#1a1a1a' : '#ffffff'
            })
            .update();
    }
}

export function switchView(view) {
    currentView = view;

    closeDetails();
    
    // Update button states
    document.querySelectorAll('.view-toggle button').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.view === view);
    });
    
    // Clean up fish animations when switching views
    const event = new CustomEvent('cleanupFishAnimations');
    document.dispatchEvent(event);
    
    const searchContainer = document.querySelector('.graph-search-container');
    if (view === 'graph') {
        document.getElementById('cy').style.display = 'block';
        document.querySelector('.compact-view').style.display = 'none';
        document.querySelector('.status-box').style.display = 'block';
        const updateEvent = new CustomEvent('updateGraph');
        document.dispatchEvent(updateEvent);
        searchContainer.style.display = 'flex';
    } else {
        document.getElementById('cy').style.display = 'none';
        document.querySelector('.compact-view').style.display = 'block';
        document.querySelector('.status-box').style.display = 'none';
        searchContainer.style.display = 'none';
        updateCompactView();
    }
}

export function updateCompactView() {
    const grid = document.getElementById('status-grid');
    if (!grid) return;

    // Get pipeline state from app.js
    const event = new CustomEvent('getPipelineState');
    document.dispatchEvent(event);
    const pipelineState = event.detail;
    
    if (!pipelineState) return;

    // Add search box if it doesn't exist
    let searchBox = document.getElementById('compact-search');
    if (!searchBox) {
        const searchContainer = document.createElement('div');
        searchContainer.style.position = 'relative';
        searchContainer.style.zIndex = '0';
        searchContainer.style.margin = '1rem 0';
        searchContainer.style.width = '100%';
        searchContainer.className = 'repo-search';
        
        searchBox = document.createElement('input');
        searchBox.id = 'compact-search';
        searchBox.type = 'text';
        searchBox.placeholder = 'Search nodes...';
        searchBox.style.width = '100%';
        searchBox.addEventListener('input', function() {
            updateCompactView();
        });
        
        searchContainer.appendChild(searchBox);
        grid.parentNode.insertBefore(searchContainer, grid);
    }

    const compactSearch = searchBox.value.toLowerCase();
    const collapsedCards = window.collapsedCards || {};

    // Group nodes by status
    const grouped = {};
    pipelineState.nodes.forEach(node => {
        if (!grouped[node.status]) {
            grouped[node.status] = [];
        }
        grouped[node.status].push(node);
    });

    grid.innerHTML = '';
    Object.entries(grouped).forEach(([status, nodes]) => {
        // Filter nodes by search
        let filteredNodes = nodes;
        if (compactSearch) {
            filteredNodes = nodes.filter(node => node.name.toLowerCase().includes(compactSearch));
        }

        // Skip empty groups
        if (filteredNodes.length === 0) return;

        // Sort nodes by number of failures (descending)
        filteredNodes.sort((a, b) => b.stats.failed - a.stats.failed);

        const card = document.createElement('div');
        card.className = `status-card ${status}`;
        if (collapsedCards[status]) {
            card.classList.add('collapsed');
        }
        
        // Create card header with collapse toggle
        const header = document.createElement('div');
        header.className = 'card-header';
        header.innerHTML = `
            <h3 style="color: ${getNodeColor(status)}; margin-bottom: 1rem;">
                ${status.toUpperCase()} (${filteredNodes.length})
            </h3>
            <button class="collapse-toggle" aria-label="Toggle collapse">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M19 9l-7 7-7-7" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </button>
        `;

        // Add click handler for collapse toggle
        const collapseToggle = header.querySelector('.collapse-toggle');
        collapseToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            card.classList.toggle('collapsed');
            collapsedCards[status] = card.classList.contains('collapsed');
            window.collapsedCards = collapsedCards;
        });

        card.appendChild(header);

        // Create card content wrapper
        const content = document.createElement('div');
        content.className = 'card-content';
        
        // Display all nodes
        filteredNodes.forEach(node => {
            const nodeItem = document.createElement('div');
            nodeItem.className = 'node-item';
            if (node.stats.failed  > 0) {
                nodeItem.setAttribute('data-repo', 'failed_logs');
            }
            nodeItem.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 0.5rem; width: 100%;">
                    <div style="font-weight: bold; font-size: 1.1em;">${node.name}</div>
                    <div style="display: flex; gap: 0.5rem; align-items: center; justify-content: flex-end; flex-wrap: wrap;">
                        <span class="badge badge-running${node.stats.live === 0 ? ' badge-inactive' : ''}">Running: ${node.stats.live}</span>
                        <span class="badge badge-success${node.stats.success === 0 ? ' badge-inactive' : ''}">Succeeded: ${node.stats.success}</span>
                        <span class="badge badge-failed${node.stats.failed === 0 ? ' badge-inactive' : ''}">Failed: ${node.stats.failed}</span>
                        ${(() => {
                            console.log('[BADGE_DEBUG] Compact view node:', node.name, 'stats:', node.stats);
                            console.log('[BADGE_DEBUG] Compact timeout value:', node.stats.timeout, 'Type:', typeof node.stats.timeout);
                            console.log('[BADGE_DEBUG] Compact OOMKilled value:', node.stats.oomkilled, 'Type:', typeof node.stats.oomkilled);
                            return '';
                        })()}
                        ${node.stats.timeout > 0 ? `<span class="badge badge-timeout">Timeout: ${node.stats.timeout}</span>` : ''}
                        ${node.stats.oomkilled > 0 ? `<span class="badge badge-oomkilled">OOM: ${node.stats.oomkilled}</span>` : ''}
                    </div>
                </div>
            `;
            nodeItem.onclick = () => {
                console.log('clicked', node.id);
                selectedNode = node.id;
                showNodeDetails(node.id);
            };
            content.appendChild(nodeItem);
        });

        card.appendChild(content);
        grid.appendChild(card);
    });
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Set initial theme
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.body.setAttribute('data-theme', savedTheme);
    const themeButton = document.querySelector('.theme-toggle');
    themeButton.innerHTML = savedTheme === 'dark' ? '☀️' : '🌙';
    
    // Initialize Cytoscape with correct theme
    const event = new CustomEvent('getCytoscape');
    document.dispatchEvent(event);
    const cy = event.detail;
    
    if (cy) {
        cy.style()
            .selector('core')
            .style({
                'background-color': savedTheme === 'dark' ? '#1a1a1a' : '#ffffff'
            })
            .update();
    }
});

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

export function getCurrentView() {
    return currentView;
}

/**
 * Runs why ready for a given node
 * @param {string} nodeId - The ID of the node
 */
window.runWhyReady = function(nodeId) {
    const whyReadyButton = document.querySelector('.action-button');
    if (whyReadyButton) {
        whyReadyButton.classList.add('why-ready-loading');
    }
    
    const event = new CustomEvent('requestWhyReady', { detail: { nodeId } });
    document.dispatchEvent(event);
};

// Helper function to escape HTML special characters
/**
 * Escapes HTML special characters
 * @param {string} unsafe - The string to escape
 * @returns {string} The escaped string
 */
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Delete functions for done repository
async function handleDeleteDoneRepo(nodeId) {
    if (!confirmDelete(`Are you sure you want to delete the entire 'done' repository for task '${nodeId}'? This action cannot be undone.`)) {
        return;
    }

    const button = document.querySelector(`.repo-container[data-repo="done"] .delete-repo-btn`);
    if (button) {
        button.classList.add('loading');
        button.disabled = true;
    }

    try {
        const result = await deleteDoneRepo(nodeId);
        showDeleteSuccess(`Successfully deleted ${result.deleted_count} items from done repository`);
        
        // Update the repo count immediately in the UI
        updateRepoCount(nodeId, 'done', result.remaining_count);
        
        // Refresh the node details to reflect the changes
        if (selectedNode === nodeId) {
            const event = new CustomEvent('requestNodeDetails', { detail: { nodeId } });
            document.dispatchEvent(event);
        }
        
        // Trigger a pipeline update to refresh the UI
        const updateEvent = new CustomEvent('requestPipelineUpdate');
        document.dispatchEvent(updateEvent);
    } catch (error) {
        showDeleteError(`Failed to delete done repository: ${error.message}`);
    } finally {
        if (button) {
            button.classList.remove('loading');
            button.disabled = false;
        }
    }
}

async function handleDeleteDoneRepoItem(nodeId, itemId) {
    if (!confirmDelete(`Are you sure you want to delete item '${itemId}' from the done repository? This action cannot be undone.`)) {
        return;
    }

    const buttons = document.querySelectorAll(`.file-item .delete-item-btn[onclick*="${itemId}"]`);
    buttons.forEach(button => {
        button.classList.add('loading');
        button.disabled = true;
    });

    try {
        const result = await deleteDoneRepoItem(nodeId, itemId);
        showDeleteSuccess(`Successfully deleted item '${itemId}' from done repository`);
        
        // Update the repo count immediately in the UI
        updateRepoCount(nodeId, 'done', result.remaining_count);
        
        // Refresh the node details to reflect the changes
        if (selectedNode === nodeId) {
            const event = new CustomEvent('requestNodeDetails', { detail: { nodeId } });
            document.dispatchEvent(event);
        }
        
        // Trigger a pipeline update to refresh the UI
        const updateEvent = new CustomEvent('requestPipelineUpdate');
        document.dispatchEvent(updateEvent);
    } catch (error) {
        showDeleteError(`Failed to delete item: ${error.message}`);
    } finally {
        buttons.forEach(button => {
            button.classList.remove('loading');
            button.disabled = false;
        });
    }
}

// Function to update repository count in the UI
function updateRepoCount(nodeId, repoName, newCount) {
    // Update in the node details if open
    if (selectedNode === nodeId) {
        const repoCountElement = document.querySelector(`.repo-container[data-repo="${repoName}"] .repo-count`);
        if (repoCountElement) {
            repoCountElement.textContent = `(${newCount} items)`;
        }
    }
    
    // Update in the cached node details
    if (nodeDetails[nodeId] && nodeDetails[nodeId].repositories && nodeDetails[nodeId].repositories[repoName]) {
        nodeDetails[nodeId].repositories[repoName].count = newCount;
    }
}

// Make delete functions available globally
window.deleteDoneRepo = handleDeleteDoneRepo;
window.deleteDoneRepoItem = handleDeleteDoneRepoItem;
window.updateRepoCount = updateRepoCount;

/**
 * Shows the why ready modal
 * @param {string} nodeId - The ID of the node
 * @param {WhyReadyResult} result - The result of the why ready command
 */
window.showWhyReadyModal = function(nodeId, result) {
    const modal = document.createElement('div');
    modal.className = 'file-view-modal';
    
    const content = document.createElement('div');
    content.className = 'modal-content';
    
    const header = document.createElement('div');
    header.className = 'modal-header';
    header.innerHTML = `
        <h3>Why Ready: ${escapeHtml(nodeId)}</h3>
        <button class="close-button" onclick="this.closest('.file-view-modal').remove()">×</button>
    `;
    
    const body = document.createElement('div');
    body.className = 'modal-body';
    
    if (result.error) {
        body.innerHTML = `<div class="error-message">${escapeHtml(result.error)}</div>`;
    } else {
        const pre = document.createElement('pre');
        pre.className = 'file-content';
        pre.textContent = result.stdout || result.stderr || 'No output available';
        body.appendChild(pre);
    }
    
    content.appendChild(header);
    content.appendChild(body);
    modal.appendChild(content);
    document.body.appendChild(modal);
};

/**
 * WebSocket message handler
 * @param {Event} event - The event object
 */
document.addEventListener('websocketMessage', function(event) {
    const message = event.detail;
    
    if (message.type === 'why_ready_result' || message.type === 'why_ready_error') {
        
        // Remove loading state from the button
        const whyReadyButton = document.querySelector('.action-button');
        
        if (whyReadyButton) {
            whyReadyButton.classList.remove('why-ready-loading');
        }
        
    }
}); 