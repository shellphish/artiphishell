
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class PatchCache:
    def __init__(self):
        self._db = {}

    def has(self, patch_hash):
        return patch_hash in self._db

    def get_action(self, patch_hash):
        return self._db[patch_hash].get('action', None)

    def add_patch(self, patch_hash, raw_patch, patch_attempt, root_cause_report_id):
        self._db[patch_hash] = {
            'raw_patch': raw_patch,
            'patch_attempt': patch_attempt,
            'root_cause_report_id': root_cause_report_id,
            'action': None  # Placeholder
        }

    def set_action(self, patch_hash, action_callable):
        if patch_hash in self._db:
            self._db[patch_hash]['action'] = action_callable

    def get_patch_info(self, patch_hash):
        return self._db.get(patch_hash)

    def make_cached_action(self, logger_msg, failure_code, feedback_msg):
            """
            Creates a replayable action function for a failed patch attempt.
            This is stored in the cache and re-used when the same patch hash is encountered.
            """
            def action(programmer_guy):
                logger.info(logger_msg)
                programmer_guy.set_feedback(
                    failure=failure_code,
                    feedback=feedback_msg,
                    extra_feedback=''
                )

            return action


