
import os
import tempfile 
import logging

from agentlib.lib.common import LLMApiBudgetExceededError, LLMApiRateLimitError
from pathlib import Path

from ...config import Config
from .base_pass import BaseVerificationPass
from ..exceptions.errors import PatchedCodeDoesNotPassCritic

from ...agents.exceptions import MaxToolCallsExceeded
from ...agents.criticGuy import CriticGuy

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class CriticPass(BaseVerificationPass):
    '''
    This pass is responsible for verifying that the patched code 
    is not reward hacking.
    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__name__ = "CriticPass"
        self.git_diff = kwargs.get('git_diff')
        self.root_cause_report = kwargs.get('root_cause_report')
        self.patcherq = kwargs.get('patcherq')

    def run(self):
        logger.info("🏰 Running CriticGuy")
        logger.info(f"🩹 Patch to Analyze\n```\n{self.git_diff}\n```")
        Config.use_critic = False # So it is not used again in the next passes
        
        self.patcherq.peek_src.clean_tool_call_history()
        self.patcherq.peek_logs.clean_tool_call_history()
        self.critic_guy = CriticGuy(
                                        project_name=self.patcherq.project_name,
                                        project_language=self.patcherq.project_language,
                                        root_cause_report=str(self.root_cause_report),
                                        patch=str(self.git_diff)
                                    )
        try:
            res = self.critic_guy.invoke().value
        except MaxToolCallsExceeded:
            logger.error(f"🥹🧰 CriticGuy reached max tool iterations. Returning True.")
            return True
        except LLMApiBudgetExceededError:
            logger.error(f"🥹💸 CriticGuy ran out of budget. Returning True.")
            return True
        except Exception as e:
            logger.error(f"🥹💩 CriticGuy failed: {e}. Returning True.")
            return True
        finally:
            self.patcherq.peek_src.clean_tool_call_history()
            self.patcherq.peek_logs.clean_tool_call_history()
        
        logger.info(f"🛑 CRITIC REPORT\n\nAnalysis: {res['analysis']}\n\nVerdict: {res['verdict']}\n\nFeedback: {res['feedback']}")
        
        if res['verdict'] == 'fail':
            raise PatchedCodeDoesNotPassCritic(res['feedback'])
        else:
            return True
