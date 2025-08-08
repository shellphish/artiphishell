"""Filter framework orchestrator."""

import logging
from typing import Dict, List, Optional
from pydantic import Field

from src.models import (
    BaseObject,
    OSSFuzzProject,
    CodeBlock,
    FilterPass,
    FilterResult,
)
from src.input import CodeRegistry

logger = logging.getLogger(__name__)

class FilterFramework(BaseObject):
    """Orchestrates the execution of filter passes over code blocks."""
    
    registered_passes: Dict[str, FilterPass] = Field(
        default_factory=dict,
        description="Dictionary of registered filter passes by name"
    )
    
    execution_order: List[str] = Field(
        default_factory=list,
        description="Order in which to execute the filter passes. Expensive filters should be later."
    )
    
    global_config: Dict = Field(
        default_factory=dict,
        description="Global configuration options for all filters"
    )
    
    def register_pass(self, filter_pass: FilterPass, *, position: Optional[int] = None) -> None:
        """Register a new filter pass.
        
        Args:
            filter_pass: The filter pass instance to register
            position: Optional position in execution order (None for append)
                     Expensive filters should be placed later in the order.
        """
        logger.info(f"Registering filter pass: {filter_pass.name}")
        self.registered_passes[filter_pass.name] = filter_pass
        
        # Handle positioning in execution order
        if filter_pass.name in self.execution_order:
            logger.debug(f"Removing existing position for {filter_pass.name}")
            self.execution_order.remove(filter_pass.name)
            
        if position is None:
            logger.debug(f"Appending {filter_pass.name} to execution order")
            self.execution_order.append(filter_pass.name)
        else:
            logger.debug(f"Inserting {filter_pass.name} at position {position}")
            self.execution_order.insert(position, filter_pass.name)
        
        logger.debug(f"Current execution order: {', '.join(self.execution_order)}")
    
    def _process_blocks_with_filter(self, blocks: List[CodeBlock], filter_pass: FilterPass) -> None:
        """Process all blocks with a single filter.
        
        This is separated to allow for future parallel processing implementation.
        
        Args:
            blocks: List of CodeBlocks to process
            filter_pass: The filter to apply to all blocks
        """
        logger.debug(f"Processing {len(blocks)} blocks with filter: {filter_pass.name}")
        try:
            results = filter_pass.apply(blocks)
            # Assign results back to blocks
            for block, result in zip(blocks, results):
                block.filter_results[filter_pass.name] = result
                logger.debug(f"Filter {filter_pass.name} assigned weight {result.weight} to {block.function_info.funcname}")
        except Exception as e:
            import traceback
            logger.error(f"Error processing blocks with filter {filter_pass.name}: {e}")
            logger.error(traceback.format_exc())
    
    def process_blocks(self, code_blocks: List[CodeBlock]) -> List[CodeBlock]:
        """Process all blocks through each filter in sequence.
        
        This processes one filter at a time across all blocks, allowing:
        1. Expensive filters to be run later in the pipeline
        2. Filters to potentially skip blocks based on earlier results
        3. Filters to look at results from previous filters across all blocks
        
        Args:
            code_blocks: List of CodeBlocks to process
            
        Returns:
            List of processed CodeBlocks with filter results
        """
        logger.info(f"Starting to process {len(code_blocks)} blocks through {len(self.execution_order)} filters")
        
        # Process one filter at a time across all blocks
        for pass_name in self.execution_order:
            try:
                if not self.registered_passes[pass_name].enabled:
                    logger.debug(f"Skipping disabled filter: {pass_name}")
                    continue
                    
                filter_pass = self.registered_passes[pass_name]
                logger.info(f"Running filter: {pass_name}")
                self._process_blocks_with_filter(code_blocks, filter_pass)
            except Exception as e:
                import traceback
                traceback.print_exc()
                logger.error(f"Error processing blocks with filter {pass_name}: {e}")
        
        logger.info("Completed processing all blocks through all filters")
        return code_blocks
    
    def calculate_priority_scores(self, code_blocks: List[CodeBlock]) -> List[CodeBlock]:
        """Calculate priority scores for code blocks based on their filter results.
        
        This is separate from processing to allow for more sophisticated scoring algorithms
        that may need to look at results across all blocks.
        
        Args:
            code_blocks: List of CodeBlocks with filter results
            
        Returns:
            Same code blocks with priority scores calculated
        """
        logger.info(f"Calculating priority scores for {len(code_blocks)} blocks")
        
        # TODO: Implement more sophisticated scoring
        # For now, just sum the weights from each filter
        for block in code_blocks:
            block_metadata = block.metadata or {}
            total_score = 0.0
            should_skip = False

            for result in block.filter_results.values():
                block_metadata.update(result.metadata)
                if result.metadata.get("is_test", False):
                    should_skip = True
                    # No need to process further results if we are skipping
                    break
                total_score += result.weight

            block.metadata = block_metadata

            if should_skip:
                block.priority_score = 0.0
                logger.debug(f"Skipped {block.function_info.funcname} because test file detected!")
            else:
                block.priority_score = total_score
                logger.debug(f"Assigned priority score {total_score} to {block.function_info.funcname}")
        
        logger.info("Completed priority score calculation")
        return code_blocks 

    def pre_process_project(self, project: OSSFuzzProject, code_registry: CodeRegistry, metadata: Dict) -> None:

        for filter_pass_name in self.execution_order:
            try:
                filter_pass = self.registered_passes[filter_pass_name]
                filter_pass.pre_process_project(project, code_registry, metadata)
            except Exception as e:
                import traceback
                traceback.print_exc()
                logger.error(f"Error pre-processing project with filter {filter_pass_name}: {e}")


    def process_project(self, project: OSSFuzzProject, code_registry: CodeRegistry, metadata: Dict) -> None:
        """Process the entire project through all filters."""


        self.info("Starting project-wide processing")

        
        # Get all code blocks from registry
        code_blocks = list(code_registry.all_code_blocks)

        # Process all blocks through each filter
        processed_blocks = self.process_blocks(code_blocks)
        
        # Calculate priority scores
        self.calculate_priority_scores(processed_blocks)
        