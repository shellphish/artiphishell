// Main application file
import { initCytoscape, updateGraph, navigateToNode, getCytoscape } from './core/graph.js';
import { connectWebSocket, sendMessage, closeWebSocket, ws, resetReconnectAttempts} from './core/websocket.js';
import { cleanupFishAnimations } from './core/animations.js';
import { 
    showNodeDetails, 
    closeDetails, 
    switchTab, 
    toggleTheme, 
    switchView, 
    getCurrentView,
    updateCompactView,
    nodeDetails,
    nodeFiles,
    selectedNode,
    activeTab,
    updateDetailsTab,
    updateFilesTab,
    nodeDetailsLoading
} from './ui/components.js';
import { PipelineState, NodeInfo, EdgeInfo, NodeStats, FileInfo, NodeStatus } from './core/models.js';

// Make navigateToNode available globally
window.navigateToNode = navigateToNode;

let pipelineState = null;
let currentView = 'graph';  // Initialize with default view

// Initialize the application
function init() {
    // Create container if it doesn't exist
    if (!document.getElementById('cy')) {
        const container = document.createElement('div');
        container.id = 'cy';
        document.body.appendChild(container);
    }

    // Add search bar
    const searchContainer = document.createElement('div');
    searchContainer.className = 'graph-search-container';
    const searchInputWrapper = document.createElement('div');
    searchInputWrapper.className = 'graph-search-input-wrapper';
    searchInputWrapper.style.position = 'relative';
    const searchIcon = document.createElement('span');
    searchIcon.className = 'graph-search-icon';
    searchIcon.textContent = '🔍';
    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.className = 'graph-search-input';
    searchInput.placeholder = 'Search nodes...';
    searchInputWrapper.appendChild(searchIcon);
    searchInputWrapper.appendChild(searchInput);
    searchContainer.appendChild(searchInputWrapper);
    document.body.appendChild(searchContainer);

    // Add search results container
    const searchResults = document.createElement('div');
    searchResults.className = 'graph-search-results';
    searchContainer.appendChild(searchResults);

    // Initialize Cytoscape
    initCytoscape();

    // Connect to WebSocket
    connectWebSocket();

    // Set up event listeners
    setupEventListeners();

    // Add Download Backup button
    const backupBtn = document.getElementById('download-backup-btn');
    if (backupBtn) {
        backupBtn.className = 'purple-backup-btn backup-btn';
        backupBtn.innerHTML = `<span style="font-size:1.2em;vertical-align:middle;">&#128190;</span>`;
        backupBtn.disabled = false;
        backupBtn.style.opacity = 1;
        backupBtn.onclick = handleBackupButtonClick;
    }

    // Add K8s Pods button
    const k8sPodsBtn = document.getElementById('k8s-pods-btn');
    if (k8sPodsBtn) {
        k8sPodsBtn.onclick = handleK8sPodsButtonClick;
    }

    // Add Node Viz button (initially hidden)
    const nodeVizBtn = document.getElementById('node-viz-btn');
    if (nodeVizBtn) {
        nodeVizBtn.onclick = handleNodeVizButtonClick;
    }
}

// Set up event listeners
function setupEventListeners() {
    // Close details button
    document.querySelector('.close-details').addEventListener('click', () => {
        closeDetails();
    });

    // Tab switching
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', (event) => {
            const tabName = event.target.dataset.tab;
            switchTab(tabName);
        });
    });

    // Status card collapse/expand
    document.addEventListener('click', (event) => {
        if (event.target.matches('.collapse-toggle')) {
            const statusCard = event.target.closest('.status-card');
            statusCard.classList.toggle('collapsed');
        }
    });

    // View toggle buttons
    document.querySelectorAll('.view-toggle button').forEach(button => {
        button.addEventListener('click', (event) => {
            const view = event.target.dataset.view;
            const viewToggle = event.target.closest('.view-toggle');
            
            // Remove active class from all buttons
            viewToggle.querySelectorAll('button').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Add active class to clicked button
            event.target.classList.add('active');
            
            // Set the data-view attribute for the sliding effect
            viewToggle.dataset.view = view;
            
            // Switch the view
            switchView(view);
            
            // Update the pipeline if we have state
            if (pipelineState) {
                updatePipeline(pipelineState);
            }
        });
    });

    // Theme toggle button
    document.querySelector('.theme-toggle').addEventListener('click', () => {
        toggleTheme();
    });

    // WebSocket message handler
    document.addEventListener('websocketMessage', (event) => {
        const message = event.detail;
        switch (message.type) {
            case 'initial_state':
            case 'pipeline_update':
                console.log('[WEBSOCKET_DEBUG] Received pipeline update:', message.data);
                // Check if any nodes have timeout or oomkilled data
                message.data.nodes.forEach(node => {
                    if (node.stats && (node.stats.timeout > 0 || node.stats.oomkilled > 0)) {
                        console.log('[WEBSOCKET_DEBUG] Node with failure subcategories:', node.name, 'stats:', node.stats);
                    }
                });
                pipelineState = new PipelineState(message.data);
                updatePipeline(pipelineState);
                break;
            case 'node_details':
                const nodeInfo = new NodeInfo(message.data);
                nodeDetails[message.nodeId] = nodeInfo;
                nodeDetailsLoading[nodeInfo.id] = false;
                if (selectedNode === nodeInfo.id && activeTab === 'details') {
                    updateDetailsTab();
                }
                break;
            case 'node_files':
                const files = message.data.map(f => new FileInfo(f));
                nodeFiles[message.nodeId] = files;
                if (selectedNode === message.nodeId && activeTab === 'files') {
                    updateFilesTab();
                }
                break;
            case 'why_ready_result':
                window.showWhyReadyModal(message.nodeId, message.data);
                break;
            case 'why_ready_error':
                alert(`Error running why-ready: ${message.error}`);
                break;
            case 'ping':
                sendMessage({ type: 'pong' });
                break;
        }
    });

    // Node selection handler
    document.addEventListener('nodeSelected', (event) => {
        showNodeDetails(event.detail.nodeId);
    });

    // Node deselection handler
    document.addEventListener('nodeDeselected', () => {
        closeDetails();
    });

    // Graph update handler
    document.addEventListener('updateGraph', () => {
        if (pipelineState) {
            updateGraph(pipelineState);
        }
    });

    // Get Cytoscape instance handler
    document.addEventListener('getCytoscape', (event) => {
        Object.defineProperty(event, 'detail', {
            value: cy,
            writable: true
        });
    });

    // Get pipeline state handler
    document.addEventListener('getPipelineState', (event) => {
        Object.defineProperty(event, 'detail', {
            value: pipelineState,
            writable: true
        });
    });

    // Cleanup fish animations handler
    document.addEventListener('cleanupFishAnimations', () => {
        cleanupFishAnimations();
    });

    // Request node details handler
    document.addEventListener('requestNodeDetails', (event) => {
        sendMessage({ type: 'request_node_files', nodeId: event.detail.nodeId });
        sendMessage({ type: 'request_node_details', nodeId: event.detail.nodeId });
    });

    // Request why-ready handler
    document.addEventListener('requestWhyReady', (event) => {
        sendMessage({ type: 'request_why_ready', nodeId: event.detail.nodeId });
    });

    // Add visibility change handler to manage reconnection
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
            // If we're disconnected, try to reconnect when the page becomes visible
            if (!ws || ws.readyState === WebSocket.CLOSED) {
                resetReconnectAttempts(); // Reset attempts when page becomes visible
                connectWebSocket();
            }
        }
    });

    // Cleanup on unload
    window.addEventListener('beforeunload', () => {
        closeWebSocket();
    });

    // Search bar variables (declare at the top for scope safety)
    const searchInput = document.querySelector('.graph-search-input');
    const searchContainer = document.querySelector('.graph-search-container');
    const searchResults = document.querySelector('.graph-search-results');
    
    // Set search bar width once, always expanded
    const expandedWidth = Math.max(200, Math.min(600, Math.floor(window.innerWidth * 0.10)));
    searchInput.parentElement.style.width = expandedWidth + 'px';
    searchResults.style.display = 'none';

    searchInput.addEventListener('input', (event) => {
        const searchTerm = event.target.value.toLowerCase();
        if (!pipelineState || !Array.isArray(pipelineState.nodes)) {
            console.error('[NodeSearch] pipelineState.nodes not available');
            searchResults.innerHTML = '';
            searchResults.style.display = 'none';
            return;
        }
        if (!searchTerm) {
            searchResults.innerHTML = '';
            searchResults.style.display = 'none';
            return;
        }
        // Find matching nodes in the cache
        const matchingNodesData = pipelineState.nodes.filter(node => {
            const nodeName = node.name || '';
            const match = nodeName.toLowerCase().includes(searchTerm);
            return match;
        });
        // Render results below the search bar
        if (matchingNodesData.length > 0) {
            searchResults.innerHTML = matchingNodesData.map(node => `
                <div class="graph-search-result-item graph-search-status-${node.status}" data-node-id="${node.id}">
                    <span class="graph-search-result-name">${node.name}</span>
                    <span class="graph-search-result-status">${node.status}</span>
                </div>
            `).join('');
        } else {
            searchResults.innerHTML = '<div class="graph-search-no-results">No results found</div>';
        }
        searchResults.style.display = 'block';
    });

    // Click handler for search results
    searchResults.addEventListener('click', (event) => {
        const item = event.target.closest('.graph-search-result-item');
        if (!item) return;
        const nodeId = item.getAttribute('data-node-id');
        // Simulate a click on the node in Cytoscape
        if (nodeId) {
            const cy = getCytoscape && getCytoscape();
            if (cy) {
                const node = cy.getElementById(nodeId);
                if (node) {
                    // Simulate tap/click event on the node
                    node.emit('tap', { target: node });
                    cy.center(node);
                }
            }
            // Optionally: close search results after click
            searchResults.innerHTML = '';
            searchResults.style.display = 'none';
            searchInput.value = '';
        }
    });

    // Update search bar position when details panel opens/closes
    document.addEventListener('nodeSelected', () => {
        searchContainer.classList.add('with-details');
    });

    document.addEventListener('nodeDeselected', () => {
        searchContainer.classList.remove('with-details');
    });
}

const taskNameText = document.querySelector('.task-name-text');
const taskIdText = document.querySelector('.task-id');
const taskNameElement = document.getElementById('task-name');
// Update pipeline visualization
function updatePipeline(data) {
    pipelineState = data instanceof PipelineState ? data : new PipelineState(data);
    
    // Update task name if available
    if (data.task_name) {
        taskNameText.textContent = data.task_name || '';
        taskIdText.textContent = data.task_id || '';
        taskNameElement.style.display = 'flex';
    } else {
        taskNameElement.style.display = 'none';
    }
    
    // Show/hide node-viz button based on availability
    const nodeVizBtn = document.getElementById('node-viz-btn');
    if (nodeVizBtn && data.node_viz_ip) {
        nodeVizBtn.style.display = 'inline-block';
        nodeVizBtn.setAttribute('data-ip', data.node_viz_ip);
    } else if (nodeVizBtn) {
        nodeVizBtn.style.display = 'none';
    }
    
    for (const node of pipelineState.nodes) {
        nodeDetails[node.id] = new NodeInfo(node);
    }
    
    currentView = getCurrentView();  // Get the current view from components
    if (currentView === 'graph') {
        updateGraph(data);
    } else {
        updateCompactView();
    }
    updateStatusCounts();
    updateLastUpdated();
}

function updateLastUpdated() {
    const now = new Date();
    const timeString = now.toLocaleTimeString();
    const dateString = now.toLocaleDateString();
    const lastUpdatedText = document.querySelector('.last-updated-text');
    if (lastUpdatedText) {
        lastUpdatedText.textContent = `Last updated: ${dateString} ${timeString}`;
    }
}

// Update status counts
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
        counts.running += node.stats.live;
        counts.success += node.stats.success;
        counts.failed += node.stats.failed;
        if (node.stats.success > 0 && node.stats.failed > 0) {
            counts.mixed++;
        }
        if (node.stats.live === 0 && node.stats.success === 0 && node.stats.failed === 0) {
            counts.pending++;
        }
    });
    
    document.getElementById('running-count').textContent = counts.running;
    document.getElementById('success-count').textContent = counts.success;
    document.getElementById('failed-count').textContent = counts.failed;
    document.getElementById('mixed-count').textContent = counts.mixed;
    document.getElementById('pending-count').textContent = counts.pending;
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', init);

// --- Backup logic ---
function showBackupButtonStatus(status, progress, isError, isDone, actions) {
    const backupBtn = document.getElementById('download-backup-btn');
    if (!backupBtn) return;
    
    // For icon-only button, we'll use title attribute to show status
    const iconColor = isError ? '#d7263d' : (progress && progress < 100 ? '#ffa726' : '#fff');
    backupBtn.className = 'purple-backup-btn backup-btn' + (progress && progress < 100 ? ' backup-btn-progress' : '');
    backupBtn.innerHTML = `<span style="font-size:1.2em;vertical-align:middle;color:${iconColor};">&#128190;</span>`;
    backupBtn.title = status || 'Download Backup';
    backupBtn.disabled = progress && progress < 100;
    backupBtn.style.opacity = backupBtn.disabled ? 0.6 : 1;
    
    // Add a subtle animation for progress
    if (progress && progress < 100) {
        backupBtn.style.animation = 'pulse 2s infinite';
    } else {
        backupBtn.style.animation = 'none';
    }
}

function downloadBackup(taskId) {
    const downloadUrl = `/api/backup/download/${taskId}`;
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    a.remove();
    showBackupButtonStatus('Backup downloaded!', 100, false, true);
    setTimeout(() => restoreBackupButton(), 2000);
}

window.downloadBackup = downloadBackup;

async function deleteBackup(taskId) {
    showBackupButtonStatus('Deleting previous backup...', 0);
    await fetch(`/api/backup/${taskId}`, { method: 'DELETE' });
    showBackupButtonStatus('Previous backup deleted.', 0);
    startNewBackup(taskId);
}

window.deleteBackup = deleteBackup;
// Helper to poll progress and update button
async function pollProgressButton(taskId) {
    let done = false;
    while (!done) {
        await new Promise(r => setTimeout(r, 1200));
        let prog = await fetch(`/api/backup/progress/${taskId}`).then(r => r.json());
        showBackupButtonStatus(prog.status, prog.progress, prog.status === 'backup failed' || prog.status === 'error');
        if (prog.status === 'ready') {
            showBackupButtonStatus('Backup ready!', 100, false, true);
            downloadBackup(taskId);  // Automatically download when ready
            done = true;
        } else if (prog.status === 'cancelled' || prog.status === 'backup failed' || prog.status === 'error') {
            showBackupButtonStatus('Backup failed or cancelled. Try again.', 100, true);
            done = true;
        }
    }
}

// Helper to start a new backup
async function startNewBackup(taskId) {
    showBackupButtonStatus('Starting new backup...', 5);
    await fetch(`/api/backup/${taskId}`, { method: 'POST' });
    showBackupButtonStatus('Backup started...', 10);
    pollProgressButton(taskId);
}

// Helper to cancel backup
async function cancelBackup(taskId) {
    showBackupButtonStatus('Cancelling backup...', 0);
    await fetch(`/api/backup/cancel/${taskId}`, { method: 'POST' });
    showBackupButtonStatus('Backup cancelled.', 0, true);
    setTimeout(() => restoreBackupButton(), 2000);
}

// Show a prompt below the button for re-download or new backup
function showBackupPrompt(taskId) {
    const modal = document.createElement('div');
    modal.className = 'file-view-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>Backup Available</h3>
                <button class="close-button" onclick="this.closest('.file-view-modal').remove()">×</button>
            </div>
            <div class="modal-body">
                <p style="margin-bottom: 1.5em; text-align: center; color: var(--text-primary);">
                    A backup is already available. Would you like to download it again or create a new backup?
                </p>
                <div style="display: flex; gap: 1em; justify-content: center;">
                    <button onclick="downloadBackup('${taskId}'); this.closest('.file-view-modal').remove();" 
                            style="background: var(--status-success); color: white; padding: 0.75em 1.5em; border-radius: 6px; border: none; cursor: pointer;">
                        Download Again
                    </button>
                    <button onclick="deleteBackup('${taskId}'); this.closest('.file-view-modal').remove();" 
                            style="background: var(--status-failed); color: white; padding: 0.75em 1.5em; border-radius: 6px; border: none; cursor: pointer;">
                        Create New Backup
                    </button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    // Add click outside to close
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });

    // Prevent clicks inside modal from closing it
    modal.querySelector('.modal-content').addEventListener('click', (e) => {
        e.stopPropagation();
    });
}

async function handleBackupButtonClick() {
    if (!pipelineState || !pipelineState.task_id) {
        showBackupButtonStatus('No pipeline task ID found.', 0, true);
        return;
    }
    const backupBtn = document.getElementById('download-backup-btn');
    const taskId = pipelineState.task_id;
    let progressInfo = await fetch(`/api/backup/progress/${taskId}`).then(r => r.json());
    let status = progressInfo.status;

    // UI logic based on status
    if (status === 'running backup' || status === 'zipping' || status === 'starting') {
        showBackupButtonStatus('Backup in progress...', progressInfo.progress, false, false, {
            cancel: () => cancelBackup(taskId)
        });
        pollProgressButton(taskId);
    } else if (status === 'ready') {
        // If backup is ready, show the modal to choose between download and new backup
        showBackupButtonStatus('Backup ready!', 100, false, true);
        showBackupPrompt(taskId);
    } else if (status === 'cancelled' || status === 'backup failed' || status === 'error') {
        showBackupButtonStatus('Previous backup failed or was cancelled. Start a new backup?', 0, true, false, {
            startNew: () => startNewBackup(taskId)
        });
    } else {
        // Not found or unknown - start a new backup
        showBackupButtonStatus('Starting new backup...', 0, false, false);
        startNewBackup(taskId);
    }
}

function restoreBackupButton() {
    const backupBtn = document.getElementById('download-backup-btn');
    if (!backupBtn) return;
    backupBtn.className = 'purple-backup-btn backup-btn';
    backupBtn.innerHTML = `<span style="font-size:1.2em;vertical-align:middle;">&#128190;</span>`;
    backupBtn.title = 'Download Backup';
    backupBtn.disabled = false;
    backupBtn.style.opacity = 1;
    backupBtn.style.animation = 'none';
}

// K8s Pods functionality
async function handleK8sPodsButtonClick() {
    try {
        const response = await fetch('/api/kubernetes/pods');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const pods = await response.json();
        showK8sPodsModal(pods);
    } catch (error) {
        console.error('Error fetching Kubernetes pods:', error);
        alert('Error fetching Kubernetes pods: ' + error.message);
    }
}

function showK8sPodsModal(pods) {
    const modal = document.createElement('div');
    modal.className = 'file-view-modal k8s-pods-modal';
    
    // Format age for display
    function formatAge(isoString) {
        if (isoString === 'N/A') return 'N/A';
        const now = new Date();
        const created = new Date(isoString);
        const diffMs = now - created;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);
        
        if (diffDays > 0) return `${diffDays}d`;
        if (diffHours > 0) return `${diffHours}h`;
        if (diffMins > 0) return `${diffMins}m`;
        return '<1m';
    }

    // Format container info
    function formatContainers(containers) {
        if (!containers || containers.length === 0) return 'N/A';
        const ready = containers.filter(c => c.ready).length;
        return `${ready}/${containers.length}`;
    }

    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>Kubernetes Pods</h3>
                <button class="close-button" onclick="this.closest('.file-view-modal').remove()">×</button>
            </div>
            <div class="modal-body">
                <table class="k8s-pods-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Status</th>
                            <th>Ready</th>
                            <th>Node</th>
                            <th>Node IP</th>
                            <th>Pod IP</th>
                            <th>Age</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${pods.map(pod => `
                            <tr>
                                <td class="pod-name" title="${pod.name}">${pod.name}</td>
                                <td><span class="pod-status ${pod.status.toLowerCase()}">${pod.status}</span></td>
                                <td>${formatContainers(pod.containers)}</td>
                                <td>${pod.node}</td>
                                <td class="node-ip">${pod.node_ip}</td>
                                <td class="pod-ip">${pod.pod_ip}</td>
                                <td>${formatAge(pod.age)}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);

    // Add click outside to close
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });

    // Prevent clicks inside modal from closing it
    modal.querySelector('.modal-content').addEventListener('click', (e) => {
        e.stopPropagation();
    });
}

// Node Viz functionality
function handleNodeVizButtonClick() {
    const nodeVizBtn = document.getElementById('node-viz-btn');
    const ip = nodeVizBtn.getAttribute('data-ip');
    if (ip) {
        const url = `http://${ip}:8080`;
        window.open(url, '_blank');
    } else {
        alert('Node Viz IP not available');
    }
} 