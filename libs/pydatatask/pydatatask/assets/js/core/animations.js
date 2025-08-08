// Fish animations module
let fishAnimations = new Map();
let fishProgress = new Map();
let animationFrame = null;

export function updateFishAnimations(cy, pipelineState) {
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
                    createFish(cy, edge, oldFish?.progress);
                    createdFish.push(edgeId);
                }
            });

        // Start animation loop
        if (animationFrame) cancelAnimationFrame(animationFrame);
        animateFish(cy);
    });
}

function createFish(cy, edge, savedProgress) {
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

function animateFish(cy) {
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

    animationFrame = requestAnimationFrame(() => animateFish(cy));
}

export function cleanupFishAnimations() {
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