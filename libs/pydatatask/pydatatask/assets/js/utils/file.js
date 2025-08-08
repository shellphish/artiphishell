// File utilities
export function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Helper function to escape HTML special characters
export function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

export async function downloadFile(nodeId, repo, filepath) {
    try {
        // For live repositories, downloading doesn't make sense - show a message instead
        if (repo === 'live') {
            alert('Download not available for live jobs. Use the View Logs button instead.');
            return;
        }
        
        if (repo === 'failed_logs') {
            repo = 'logs';
        }
        const response = await fetch(`http://${window.location.host}/api/nodes/${nodeId}/files/${repo}/${filepath}`);
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

export async function viewFile(nodeId, repoName, filepath) {
    try {
        // Live repositories should use viewLivePodLogs directly
        if (repoName === 'live') {
            console.warn('viewFile called with live repository - use viewLivePodLogs instead');
            return;
        }
        
        if (repoName === 'failed_logs') {
            repoName = 'logs';
        }
        const response = await fetch(`http://${window.location.host}/api/nodes/${nodeId}/files/${repoName}/${filepath}`);
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
                <div class="modal-body" style="max-height: 80vh; overflow-y: auto;">
                    <pre class="file-content" style="margin: 0; white-space: pre-wrap; word-wrap: break-word;">${escapeHtml(content)}</pre>
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

export async function viewLivePodLogs(nodeId, jobId) {
    let refreshInterval = null;
    let currentFull = false;
    let autoRefreshEnabled = true; // Enable auto-refresh by default
    
    async function fetchLogs(full = false) {
        const url = `/api/nodes/${nodeId}/live/${jobId}/logs${full ? '?full=true' : ''}`;
        const response = await fetch(url);
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to fetch pod logs: ${errorText}`);
        }
        return await response.json();
    }
    
    async function updateLogs(modal, full = false) {
        try {
            const statusElement = modal.querySelector('.logs-status');
            if (statusElement) {
                statusElement.textContent = 'Refreshing...';
                statusElement.style.color = 'var(--text-secondary)';
            }
            
            const data = await fetchLogs(full);
            const logs = data.logs;
            currentFull = full;
            
            // Update modal with actual logs
            const modalBody = modal.querySelector('.modal-body');
            const wasScrolledToBottom = isScrolledToBottom(modalBody.querySelector('.logs-container'));
            
            modalBody.innerHTML = `
                <div class="logs-controls" style="margin-bottom: 1rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem;">
                    <div style="display: flex; gap: 0.5rem; align-items: center;">
                        <button class="refresh-button" style="background: var(--status-success); color: white; padding: 0.5rem 1rem; border: none; border-radius: 4px; cursor: pointer; font-size: 0.875rem;">
                            🔄 Refresh
                        </button>
                        <button class="full-log-button" style="background: ${full ? 'var(--status-mixed)' : 'var(--status-running)'}; color: white; padding: 0.5rem 1rem; border: none; border-radius: 4px; cursor: pointer; font-size: 0.875rem;">
                            ${full ? '📄 Tail Logs' : '📜 Full Logs'}
                        </button>
                        <label style="display: flex; align-items: center; gap: 0.5rem; color: var(--text-primary); font-size: 0.875rem;">
                            <input type="checkbox" class="auto-refresh-checkbox" ${autoRefreshEnabled ? 'checked' : ''}>
                            Auto-refresh (1min)
                        </label>
                    </div>
                    <div class="logs-status" style="font-size: 0.875rem; color: var(--text-secondary);">
                        ${full ? 'Full log' : `Last ${data.tail_lines || 1000} lines`} • Updated: ${new Date(data.timestamp).toLocaleTimeString()}
                    </div>
                </div>
                <div class="logs-container" style="max-height: 70vh; overflow-y: auto; background: #1e1e1e; padding: 1rem; border-radius: 4px;">
                    <pre class="pod-logs" style="margin: 0; white-space: pre-wrap; word-wrap: break-word; color: #d4d4d4; font-family: 'Courier New', monospace; font-size: 0.875rem; line-height: 1.4;">${escapeHtml(logs)}</pre>
                </div>
            `;
            
            // Auto-scroll to bottom if user was at bottom or if this is initial load
            const logsContainer = modalBody.querySelector('.logs-container');
            if (wasScrolledToBottom || !modal.hasAttribute('data-loaded')) {
                logsContainer.scrollTop = logsContainer.scrollHeight;
                modal.setAttribute('data-loaded', 'true');
            }
            
            // Add event listeners for controls
            const refreshButton = modalBody.querySelector('.refresh-button');
            const fullLogButton = modalBody.querySelector('.full-log-button');
            const autoRefreshCheckbox = modalBody.querySelector('.auto-refresh-checkbox');
            
            refreshButton.addEventListener('click', () => updateLogs(modal, currentFull));
            
            fullLogButton.addEventListener('click', () => {
                updateLogs(modal, !currentFull);
            });
            
            autoRefreshCheckbox.addEventListener('change', (e) => {
                autoRefreshEnabled = e.target.checked;
                if (e.target.checked) {
                    startAutoRefresh(modal);
                } else {
                    stopAutoRefresh();
                }
            });
            
        } catch (error) {
            console.error('Error updating logs:', error);
            const modalBody = modal.querySelector('.modal-body');
            modalBody.innerHTML = `
                <div style="text-align: center; padding: 2rem; color: var(--status-failed);">
                    <div style="font-size: 1.2rem; margin-bottom: 1rem;">❌ Failed to load pod logs</div>
                    <div style="font-size: 0.9rem; color: var(--text-secondary);">${error.message}</div>
                    <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 1rem;">
                        This feature requires running in Kubernetes with proper permissions.
                    </div>
                </div>
            `;
        }
    }
    
    function isScrolledToBottom(container) {
        if (!container) return true;
        return container.scrollTop + container.clientHeight >= container.scrollHeight - 5; // 5px tolerance
    }
    
    function startAutoRefresh(modal) {
        stopAutoRefresh(); // Clear any existing interval
        refreshInterval = setInterval(() => {
            updateLogs(modal, currentFull);
        }, 60000); // 60 seconds
    }
    
    function stopAutoRefresh() {
        if (refreshInterval) {
            clearInterval(refreshInterval);
            refreshInterval = null;
        }
    }
    
    try {
        // Show loading modal first
        const modal = document.createElement('div');
        modal.className = 'file-view-modal';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Pod Logs - ${nodeId} (Job: ${jobId})</h3>
                    <button class="close-button" onclick="event.stopPropagation(); this.closest('.file-view-modal').remove()">×</button>
                </div>
                <div class="modal-body">
                    <div class="loading-logs" style="text-align: center; padding: 2rem;">
                        <div style="font-size: 1.2rem; margin-bottom: 1rem;">Loading pod logs...</div>
                        <div style="font-size: 0.9rem; color: var(--text-secondary);">Getting logs from Kubernetes pod</div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Clean up interval when modal is closed
        modal.addEventListener('remove', stopAutoRefresh);
        
        // Add click outside to close
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                e.stopPropagation();
                stopAutoRefresh();
                modal.remove();
            }
        });

        // Prevent clicks inside modal from closing it
        modal.querySelector('.modal-content').addEventListener('click', (e) => {
            e.stopPropagation();
        });
        
        // Override close button to clean up interval
        const closeButton = modal.querySelector('.close-button');
        closeButton.addEventListener('click', () => {
            stopAutoRefresh();
            modal.remove();
        });
        
        // Load initial logs
        await updateLogs(modal, false);
        
        // Start auto-refresh by default
        if (autoRefreshEnabled) {
            startAutoRefresh(modal);
        }
        
    } catch (error) {
        console.error('Error viewing pod logs:', error);
        alert(`Failed to load pod logs: ${error.message}`);
        stopAutoRefresh();
    }
} 