#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from typing import Dict, Optional

os.chdir(os.path.dirname(__file__))

import agentlib
from agentlib.lib import tools
from agentlib import (
    Agent, PlanExecutor,
    AgentResponse,
    AgentPlan, AgentPlanStep,
    AgentPlanStepAttempt,
    CodeExtractor, WebConsoleLogger
)

# Create a plan for the agent to follow.
# We will hardcode our plan as a series of steps
PLAN = AgentPlan(steps=[
    AgentPlanStep(
        # Description can contain anything you want to describe the current step
        description='Determine what needs to change to remove the bug',
    ),
    AgentPlanStep(
        # Name allows you to quickly detect what step is being executed
        name='patched_function',
        description='Create a new version of the function with the bug removed, but functionally equivalent. Minimize the changes made. Only output the new version of the function, not the patch file. We will do that after this step.',

        # Output parser lets you override the output for this one step
        # This can be used to extract structure and then post process
        # by overriding the `process_step_result` method
        # Call `res.save()` in `on_step_*` to save any changes to the response
        output_parser=CodeExtractor(),
    ),
    AgentPlanStep(
        description="Read through the Proposed Fixed Version and try to pick out any flaws in the patch. Walk through the code and try to find any potential edgecases or difference in behavior which are unwanted because they change normal functionality.",
    )
])

class PatchTest(PlanExecutor[str, str]):
    """
    This agent will follow the steps above.
    """
    __SYSTEM_PROMPT_TEMPLATE__ = 'patch_agent.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'patch_agent.user.j2'

    source: Optional[str]
    bug_desc: Optional[str]
    modified_source: Optional[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def get_step_input_vars(self, step: AgentPlanStep) -> dict:
        # Template variables for the prompts
        return dict(
            **super().get_step_input_vars(step),
            source = self.source,
            bug_desc = self.bug_desc,
            modified_source = self.modified_source
        )
    
    def process_step_result(
            self,
            step: AgentPlanStep,
            attempt: AgentPlanStepAttempt
    ):
        super().process_step_result(step, attempt)
        res = attempt.result
        # This is where you can post process the output of a step
        # For example, you can save the output to a file
        # or extract some information from the output
        # or even modify the output
        if step.name == 'patched_function':
            print('Patched function:', repr(res))
            self.modified_source = res

        # If you modified the attempt, result, or step
        step.save()
        return True # Final judgement on whether the step was successful

SOURCE = '''
int main() {
    char buf[10];
    gets(buf);
    printf("Hello Friend %s\n", buf);
}'''
BUG_DESC = 'Buffer overflow in the call to gets()'

SOURCE = '''
static bool tipc_crypto_key_rcv(struct tipc_crypto *rx, struct tipc_msg *hdr)
{

	struct tipc_crypto *tx  = NULL;
	struct tipc_aead_key *skey = NULL;
	u16 key_gen = msg_key_gen(hdr);
	u32 size = msg_data_sz(hdr);
	u8 *data = msg_data(hdr);
	unsigned int keylen;
	
	if(rx->net){
		tx = tipc_net(rx->net)->crypto_tx;
	}
	keylen = ntohl(*((__be32 *)(data + TIPC_AEAD_ALG_NAME)));

	spin_lock(&rx->lock);
	if (unlikely(rx->skey || (key_gen == rx->key_gen && rx->key.keys))) {
		pr_err("%s: key existed <%p>, gen %d vs %d\n", rx->name,
		       rx->skey, key_gen, rx->key_gen);
		goto exit;
	}

	/* Allocate memory for the key */
	skey = kmalloc(size, GFP_ATOMIC);
	if (unlikely(!skey)) {
		pr_err("%s: unable to allocate memory for skey\n", rx->name);
		goto exit;
	}

	/* Copy key from msg data */
	skey->keylen = keylen;
	memcpy(skey->alg_name, data, TIPC_AEAD_ALG_NAME);
	memcpy(skey->key, data + TIPC_AEAD_ALG_NAME + sizeof(__be32),
	       skey->keylen);

	rx->key_gen = key_gen;
	rx->skey_mode = msg_key_mode(hdr);
	rx->skey = skey;
	rx->nokey = 0;
	mb(); /* for nokey flag */

exit:
	spin_unlock(&rx->lock);
	/* Schedule the key attaching on this crypto */
	if (rx->net){
	if (likely(skey && queue_delayed_work(tx->wq, &rx->work, 0)))
		return true;
	}
	return false;
}
'''
bug_desc = '''
The vulnerability described in the post is a heap overflow vulnerability in the TIPC module of the Linux Kernel. The specific lines of code involved in the vulnerability are within the `tipc_crypto_key_rcv` function. Here are the key details:

1. Lines of code involved:
   - Line 2: `u16 size = msg_data_sz(hdr);` - Retrieves the size of the message payload from the header.
   - Line 3: `skey = kmalloc(size, GFP_ATOMIC);` - Allocates memory for the key using the size obtained from the header.
   - Line 4: `skey->keylen = ntohl(*((__be32 *)(data + TIPC_AEAD_ALG_NAME)));` - Copies the key length from the message data.
   - Line 5: `memcpy(skey->key, data + TIPC_AEAD_ALG_NAME + sizeof(__be32), skey->keylen);` - Copies the key data from the message using the key length.
   - Line 6: `if (unlikely(size != tipc_aead_key_size(skey))) { ... }` - Performs a sanity check on the size after the copy has already taken place.

2. Technical classification of the bug:
   - The vulnerability is classified as a heap overflow vulnerability.

3. Steps and codepath that make it vulnerable:
   - The function retrieves the size of the message payload from the header (Line 2) and uses it to allocate memory for the key (Line 3).
   - The key length is copied from the message data (Line 4) without proper validation against the allocated size.
   - The key data is then copied from the message using the key length (Line 5), potentially writing beyond the allocated memory if the key length is larger than the allocated size.
   - The sanity check on the size (Line 6) is performed after the copy has already taken place, making it ineffective in preventing the overflow.

The vulnerability arises from the lack of proper validation of the key length against the allocated size before copying the key data. An attacker can craft a malicious message with a small payload size to allocate a small buffer but specify a large key length to overflow the buffer and write beyond the allocated memory.

The patch for the vulnerability moves the size validation to take place before the copy and adds additional checks for the minimum packet size and the supplied key size to mitigate the issue.
'''

def main():

    # Path to save agent data to
    agent_path = '/tmp/patch_agent.json'
    plan = PLAN.save_copy()

    agent: PatchTest = PatchTest.reload_id_from_file_or_new(
        agent_path,
        source=SOURCE,
        goal='patch the program',
        bug_desc=BUG_DESC,
        plan=plan
    )

    agent.use_web_logging_config()

    agent.warn(f'========== Agents plan ==========\n')
    print(agent)
    print(agent.plan)

    agent.warn(f'========== Running agent ==========\n')

    res = agent.invoke()
    print(res)


if __name__ == '__main__':
    main()




