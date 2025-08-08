// Keep track of existing fish
const activeFish = new Map();
// Keep track of animation states
const animationStates = new Map();

function createFishForPath(path) {
    const pathId = path.getAttribute('d');
    
    // If fish already exists for this path, return
    if (activeFish.has(pathId)) {
        return;
    }
    
    // Get the SVG element
    const svg = path.closest('svg');
    if (!svg) return;
    
    // If the path doesn't have an ID, create one
    if (!path.id) {
        path.id = "path-" + Math.random().toString(36).substr(2, 9);
    }
    
    // Create a new group element for the fish
    const fishGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
    fishGroup.setAttribute("class", "fish-svg");
    
    // Use the Artiphishell logo as the fish
    // We'll use an image element to reference the SVG file
    const fishImage = document.createElementNS("http://www.w3.org/2000/svg", "image");
    fishImage.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", "assets/Artiphishell_black.svg");
    fishImage.setAttribute("width", "2%");
    fishImage.setAttribute("height", "2%");
    fishImage.setAttribute("x", "-10");  // Center the image
    fishImage.setAttribute("y", "-5");   // Center the image
    
    // Apply a filter to match the theme
    const isDarkMode = document.documentElement.getAttribute("data-theme") === "dark";
    if (isDarkMode) {
        fishImage.setAttribute("filter", "invert(80%) sepia(100%) saturate(100%) hue-rotate(180deg) brightness(100%) contrast(100%)");
    } else {
        fishImage.setAttribute("filter", "invert(42%) sepia(93%) saturate(1352%) hue-rotate(87deg) brightness(119%) contrast(119%)");
    }
    
    fishGroup.appendChild(fishImage);
    
    // Create an animateMotion element to move the fish along the path
    const animateMotion = document.createElementNS("http://www.w3.org/2000/svg", "animateMotion");
    
    // Check if we have a saved animation state for this path
    let animationDelay = 0;
    if (animationStates.has(pathId)) {
        // Calculate a delay based on the saved state to make animation continue from where it left off
        const savedState = animationStates.get(pathId);
        const elapsedTime = (Date.now() - savedState.timestamp) / 1000; // Convert to seconds
        animationDelay = -(elapsedTime % 4); // Negative delay to start from the right position in the 4s cycle
    } else {
        // For new animations, save the initial state
        animationStates.set(pathId, {
            timestamp: Date.now(),
            pathId: pathId
        });
    }
    
    animateMotion.setAttribute("dur", "4s");
    animateMotion.setAttribute("repeatCount", "indefinite");
    animateMotion.setAttribute("rotate", "auto");
    if (animationDelay !== 0) {
        animateMotion.setAttribute("begin", animationDelay + "s");
    }
    
    // Create a mpath element to reference the original path
    const mpath = document.createElementNS("http://www.w3.org/2000/svg", "mpath");
    mpath.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", "#" + path.id);
    
    animateMotion.appendChild(mpath);
    fishGroup.appendChild(animateMotion);
    
    // Add the fish to the SVG
    svg.appendChild(fishGroup);
    activeFish.set(pathId, fishGroup);
}

function updateFishAnimations() {
    const currentPaths = new Set();
    
    // Find all active paths
    const paths = document.querySelectorAll('path');
    
    paths.forEach(path => {
        const pathId = path.getAttribute('d');
        if (!pathId) return;
        
        // Get stroke color from computed style
        const style = window.getComputedStyle(path);
        const stroke = style.stroke;
        
        // Check for both hex and rgb formats of the active colors
        if (stroke === '#ecf0f1' || stroke === 'rgb(236, 240, 241)') {
            currentPaths.add(pathId);
            createFishForPath(path);
        }
    });
    
    // Remove fish that are no longer needed
    for (const [pathId, fish] of activeFish.entries()) {
        if (!currentPaths.has(pathId)) {
            fish.remove();
            activeFish.delete(pathId);
            // Keep the animation state in case the path comes back
        }
    }
}

// Periodically update animation states to keep them current
setInterval(() => {
    for (const [pathId, fish] of activeFish.entries()) {
        if (animationStates.has(pathId)) {
            // Update the timestamp to the current time
            animationStates.get(pathId).timestamp = Date.now();
        }
    }
}, 1000); // Update every second

// Watch for changes in the graph
const observer = new MutationObserver((mutations) => {
    let shouldUpdate = false;
    
    for (const mutation of mutations) {
        // Only update if there are actual changes to the DOM structure
        if (mutation.type === 'childList' && 
            (mutation.addedNodes.length > 0 || mutation.removedNodes.length > 0)) {
            const paths = document.querySelectorAll('path');
            if (paths.length > 0) {
                shouldUpdate = true;
                break;
            }
        }
    }
    
    if (shouldUpdate) {
        // Save current animation states before updating
        for (const [pathId, fish] of activeFish.entries()) {
            if (!animationStates.has(pathId)) {
                animationStates.set(pathId, {
                    timestamp: Date.now(),
                    pathId: pathId
                });
            }
        }
        
        // Update the animations
        updateFishAnimations();
    }
});

// Start observing after a short delay to ensure the graph is loaded
setTimeout(() => {
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
    // Initial check for paths
    updateFishAnimations();
}, 1000);

// Add window resize handler to update fish positions
window.addEventListener('resize', () => {
    updateFishAnimations();
});

// Update fish when theme changes
const observer2 = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
        if (mutation.attributeName === 'data-theme') {
            updateFishAnimations();
        }
    });
});

// Start observing theme changes
observer2.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['data-theme']
});
 