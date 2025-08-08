// Color utilities
export function getNodeColor(status) {
    const colors = {
        running: '#2ecc71',
        running_failed: '#e74c3c',
        running_mixed: '#9b59b6',
        success: '#3498db',
        failed: '#e74c3c',
        mixed: '#9b59b6',
        pending: '#95a5a6'
    };
    return colors[status] || colors.pending;
}

export function getNodeBorderColor(status) {
    const borderColors = {
        running_failed: '#2ecc71',
        running_mixed: '#2ecc71',
        running: '#2c3e50',
        success: '#2c3e50',
        failed: '#2c3e50',
        mixed: '#2c3e50',
        pending: '#2c3e50'
    };
    return borderColors[status] || borderColors.pending;
} 