// Delete API utility functions

/**
 * Delete entire done repository for a node
 * @param {string} nodeId - The node ID
 * @returns {Promise<Object>} - Response from the API
 */
export async function deleteDoneRepo(nodeId) {
    try {
        const response = await fetch(`/api/nodes/${nodeId}/repos/done`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Error deleting done repository:', error);
        throw error;
    }
}

/**
 * Delete specific item from done repository
 * @param {string} nodeId - The node ID
 * @param {string} itemId - The item ID to delete
 * @returns {Promise<Object>} - Response from the API
 */
export async function deleteDoneRepoItem(nodeId, itemId) {
    try {
        const response = await fetch(`/api/nodes/${nodeId}/repos/done/${encodeURIComponent(itemId)}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Error deleting done repository item:', error);
        throw error;
    }
}

/**
 * Show confirmation dialog for deletion
 * @param {string} message - Confirmation message
 * @returns {boolean} - User confirmation
 */
export function confirmDelete(message) {
    return confirm(message);
}

/**
 * Show success message for deletion
 * @param {string} message - Success message
 */
export function showDeleteSuccess(message) {
    // Create a temporary notification
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--status-success);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: var(--shadow-md);
        z-index: 10000;
        animation: slideIn 0.3s ease;
        max-width: 300px;
    `;
    notification.textContent = message;
    
    // Add CSS animation keyframes if not already present
    if (!document.querySelector('#delete-notifications-style')) {
        const style = document.createElement('style');
        style.id = 'delete-notifications-style';
        style.textContent = `
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes slideOut {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }
        `;
        document.head.appendChild(style);
    }
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 3000);
}

/**
 * Show error message for deletion
 * @param {string} message - Error message
 */
export function showDeleteError(message) {
    // Create a temporary notification
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--status-failed);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: var(--shadow-md);
        z-index: 10000;
        animation: slideIn 0.3s ease;
        max-width: 300px;
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Remove after 5 seconds (longer for error messages)
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 5000);
} 