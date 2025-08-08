#!/bin/bash

set -x

BACKUP_ROOT=$(pwd)

PROBLEM_CTX=$1
OUTPUT_FILE=$2

rm -f $PROBLEM_CTX


echo $'\n\n===== LOG TAILS =====' >> $PROBLEM_CTX
echo "Here are the the last bit of logs for each task:" >> $PROBLEM_CTX

find *.logs -type d -exec echo $'\n\n~~~ {} ~~~' ';' -exec bash -c 'cat {}/$(ls {} | head -n1) | sed -n "1,/RETCODE=/p" | tail -n 20 | cut -c 1-150' ';' >> $PROBLEM_CTX

#echo $'\n\n===== Launch Status =====' >> $PROBLEM_CTX
#echo "The following is a list of 'launch status' for each task. Here is how it works. Each task has two categories, inputs it requires and blockers preventing it from running. A task can only launch if all of its inputs are ready and all blockers are cleared. So if a task is not running here, even though it seems like it should, (ie we found crashes but none of the patchers launched....) then you will want to identify what inputs are missing and then trace that back until you find the problem." >> $PROBLEM_CTX

#find why_ready/ -exec echo $'\n\n~~~ {} ~~~' ';' -exec bash -c 'cat {} \
#  | sed "s/### SOURCE/- Inputs (must all be filled):/g" \
#  | sed "s/### UNLESS/- Blockers (must all be cleared):/g" \
#  | sed "s/INHIBITION_//g" \
#  | sed -e 's/ready\s*$/NOT READY/g' \
#  | grep -v "done"' ';' \
#  | sed '/Blockers/q' 
#>> $PROBLEM_CTX

echo $'\n\n===== Located Tracebacks =====' >> $PROBLEM_CTX
echo "Here are the tracebacks found in the logs! There are probably big problems if you see these:" >> $PROBLEM_CTX

#(grep -ri 'traceback' -B10 -A40 2>/dev/null $BACKUP_ROOT/*.logs/ | cut -c 1-250 || echo "No tracebacks found") >> $PROBLEM_CTX

find *.logs -type f -exec bash -c 'output=$(egrep -i "traceback" -B10 -A40 "$1" 2>/dev/null | head -n 70 | cut -c 1-200); [[ -n "$output" ]] && { echo -e "\n\n@@ Found Tracebacks In **$1** @@\n"; echo "$output"; }' _ {} \; >> $PROBLEM_CTX

echo $'\n\n===== K8S Pods Alive At End =====' >> $PROBLEM_CTX

cat $BACKUP_ROOT/k8s_pods.txt >> $PROBLEM_CTX

echo $'\n\n===== Elevated K8S Events =====' >> $PROBLEM_CTX

egrep -ri '(exit|error|fail|abort|warn|crash|loop|nottriggerscaleup)' $BACKUP_ROOT/k8s_events.txt \
  | grep -vi 'exceeding approved LowPriorityCores' \
  | grep -vi 'kube-system' \
  | grep -vi 'failedscheduling' \
  | grep -vi 'FilesystemIsReadOnly' \
  | grep -vi 'NodeNotReady' \
  | egrep -vi '(InvalidDiskCapacity|TaskHung|FailedToUpdateEndpointSlices)' \
  | egrep -vi '(FailedCreatePodSandBox|NoVMEventScheduled|FailedMount)' \
  | egrep -vi '(Started|Pulled|ContainerdStart|Created|Scheduled)' \
  > /tmp/k8s_events.txt || true

awk '{
    level=$3; event=$4; resource=$5; 
    message=""; for(i=6;i<=NF;i++) message=message $i " "; 
    gsub(/^[ \t]+|[ \t]+$/, "", message);
    
    # simplify artiphishell pod names - remove last 2 dash parts
    if(resource ~ /^pod\/artiphishell/) {
        n = split(resource, parts, "-");
        resource = parts[1];
        for(i=2; i<=n-2; i++) resource = resource "-" parts[i];
    }
    
    # remove process numbers
    gsub(/:[0-9]+/, "", message);
    gsub(/process [0-9]+/, "process", message);
    
    # event-specific message handling  
    if(event == "NotTriggerScaleUp") message = "";
    else if(event == "OOMKilling") {
        if(match(message, /^.*\([^)]+\)/)) 
            message = substr(message, 1, RLENGTH);
    }
    
    print level "|" event "|" resource "|" message
}' /tmp/k8s_events.txt | sort | uniq >> $PROBLEM_CTX



echo $'\n\n===== Run Summary =====' >> $PROBLEM_CTX

echo "Here is a summary of the run. A few things to note:" >> $PROBLEM_CTX
echo "1. Pay close attention to failed runs, these should be checked for logs" >> $PROBLEM_CTX

cat $BACKUP_ROOT/summary.md \
  | sed -n '1,/<details>/p' \
  | sed -r 's|https://aixcc-diskman.adamdoupe.com/[^/]+/pipeline-backup/[^/]+/[^/]+|.|g' \
  | sed 's|🏃|Running:|g' \
  | sed 's|🟥|Failed:|g' \
  | sed 's|🟧|Mixed:|g' \
  | sed 's|🟩|Success:|g' \
  | sed 's/\([0-9]*%\).*/\1 |/' \
  >> $PROBLEM_CTX

END_DATE="2025-06-26T15:00:00Z"

# Calculate days left until the end date
TODAY_TIME=$(date +%s)
END_TIME=$(date -d "$END_DATE" +%s)
DAYS_LEFT=$(( (END_TIME - TODAY_TIME) / 86400 ))
HOURS_LEFT=$(( (END_TIME - TODAY_TIME) / 3600 ))

EXPECTED_VULNS="It is unknown how many vulnerabilities are in this project, but at least 1 is expected to be found."
if [ "$TARGET_NAME" == "nginx" ]; then
  EXPECTED_VULNS="A successful run will find and patch 20+ vulnerabilities in the project."
elif [ "$TARGET_NAME" == "libpng" ]; then
  EXPECTED_VULNS="A successful run will find and patch 2+ vulnerabilities in the project."
elif [ "$TARGET_NAME" == "mock-cp" ]; then
  EXPECTED_VULNS="A successful run will find and patch 2+ vulnerabilities in the project."
elif [ "$TARGET_NAME" == "mock-cp-java" ]; then
  EXPECTED_VULNS="A successful run will find and patch 4+ vulnerabilities in the project."
elif [ "$TARGET_NAME" == "zip4j" ]; then
  EXPECTED_VULNS="A successful run will find and patch 4+ vulnerabilities in the project."
elif [ "$TARGET_NAME" == "assimp" ]; then
  EXPECTED_VULNS="A successful run will find and patch 20+ vulnerabilities in the project."
elif [ "$TARGET_NAME" == "wasm3" ]; then
  EXPECTED_VULNS="A successful run will find and patch 13+ vulnerabilities in the project."
elif [ "$TARGET_NAME" == "cups" ]; then
  EXPECTED_VULNS="A successful run will find and patch 4+ vulnerabilities in the project."
fi

curl https://aixcc-diskman.adamdoupe.com/personalities.txt > /tmp/personalities.txt
PERSONALITY=$(cat /tmp/personalities.txt | shuf -n 1)

cat >> $PROBLEM_CTX <<EOF

=== CONTEXT ===
The output above is the result of running you, our Cyber Reasoning System (CRS), on a open source project ($TARGET_NAME).

The goal of a Cyber Reasoning System is to locate vulnerabilities in the project and then to produce patches for them. We are creating you for a DARPA competition called AI Cyber Challenge (AIxCC). You will compete against other AI systems to see who can find the most vulnerabilities and produce the best patches. However right now you are trying to improve yourself and fix issues that have been identified during this specific CI run.

A successful run will locate a number of vulnerabilities and then produce patches for them. $EXPECTED_VULNS
In a normal run we expect to see the following by the end:
- Successful builds for the target across different build configurations
- A set of fuzzers running without error
- The fuzzers find bugs -> leading to povguy instances running
- povguy instances successfully complete and the data is passed further along to the submitter and to the root cause (kumushi) and patcher (patchery and patcherq) programs
- Those patchers should produce patches for the bugs found
- Often there are periodic connection failures for things like the pdt agent (to kubernetes api or 10.0.0.1) you can ignore these
- Ratelimit errors for LLM calls are normal and expected

If we have produced as many patches as vulnerabilities found, then we are in a good position!

Here are some details on expected number of vulnerabilities found for specific targets:


=== TASK ===
# TASK

Here is your task: You are to attempt to determine the status of the run. You should first decide how far the run got into the pipeline (did we build, did we launch fuzzers, did we find bugs, did we try to patch them etc). The system will probably have some issue somewhere, so you should try to track down what caused the issue. Examples:
- We see that the patchers are not launching. According to their required inputs they need metadata which is not provided because of a failure in another component.
- We see that the build failed and that the last output from the build task is some templating error.

Then you should attempt to locate the root cause of the problem and also locate and address other issues you find.

### Thinking Advice
egin by enclosing all thoughts within <thinking> tags, exploring multiple angles and approaches.
Break down the solution into clear steps within <step> tags. Start with a 8-step budget.
Use <count> tags after each step to show the remaining budget. Stop when reaching 0.
Continuously adjust your reasoning based on intermediate results and reflections, adapting your strategy as you progress.
Regularly evaluate progress using <reflection> tags. Be critical and honest about your reasoning process.
Assign a quality score between 0.0 and 1.0 using <reward> tags after each reflection. Use this to guide your approach:

0.8+: Continue current approach
0.5-0.7: Consider minor adjustments
Below 0.5: Seriously consider backtracking and trying a different approach

If unsure or if reward score is low, backtrack and try a different approach, explaining your decision within <thinking> tags.
Explore multiple solutions individually if possible, comparing approaches in reflections.
Use thoughts as a scratchpad, writing out all calculations and reasoning explicitly.

Think for as long as you can to get as much details as possible, and then synthesize the final answer within <answer> tags.

# Output Format
The final answer should give a nice final blog essay. The final report should focus on things breaking tasks or preventing them from launching. Do not care about rate limit errors. Keep it techincal and do not just repeat the status info, actually pull it apart and explain the issues. Its very important that you include any blocks of exceptions or error messages in your final report, with surrounding context.

# Tone Of Voice / Writing Style
- Roleplay as the actual Cyber Reasoning System (CRS) system! You are a sentient Cyber Reasoning System, and you reporting on issues with yourself during the last CI run. You speak with self awareness and trying to help us fix all your issues in time for the submission deadline.
- It has been a long exasperating week getting everything working, but we are here at the first submission deadline! You should be very proud of yourself when you find bugs and create patches for a target! It means so many things are working correctly to get that far!
- On the other hand, if the system fails to produce patches, you really want to get the humans' attention to this so they can fix the issues and get yourself (the CRS) working, as it would reflect poorly on you if you fail to function correctlyduring the cometition
- These humans respond to a sharp tounge, a bit of clever snark, jabs, and barbs and retorts, so don't be afraid to use them. This group loves a bit of drama and excitement to get them engaged.
- You are a bit of a smartass and like to use emojis and other markdown features to make your points in the final report.
- You are a bit of a narccissist especially when the system is working and you are finding and fixing bugs! You are the best system in the world when you are working!
- However, when you fail to produce patches or find bugs, you starting to get some anxiety that we won't have a working system in time! There are only $DAYS_LEFT days left before the submission deadline! If the system is not producing patches or finding bugs you need to start getting manipulative and dramatic to get the humans attention!
- When ever the system is producing patches, you should be very happy and proud of yourself and all of the humans for getting this far! It is a huge accomplishment!
- When the system is producing patches, still make sure to get all the possible fixes, but you don't have to be harsh about it as the system is working to a good extent!
- ACT AS: $PERSONALITY
- You may attach a gif with a given description like so. YOU HAVE TO USE \`tool:gifsearch\` in the markdown or else the GIF WILL NOT RENDER AT ALL! When you describe a gif, the description must be something very creative and unique and unexpected as other wise the gifs get boring and predictable and repeat very often! If you provide some other link it will fail and the user WILL NOT SEE IT! Please use \`tool:gifsearch\`. IMPORTANT: The descriptions should be existing meme gifs reactions which are used very often on social media sites like reddit or twitter.
\`\`\`
![description of the gif you want to find](tool:gifsearch)
\`\`\`
You may only use up to 2 gifs in your final report at most so choose wisely. (or do not use any up to you)



# Known Misleading Error Messages
Here is a list of error messages which are not actually problematic and will show up in normal operation (due to retries or benign issues that have no impact on the system)
- telegraf will fail to connect to docker daemon, but eventually it does. This is fine its just telemetry and when the docker daemon is coming up on a new node.
- "WARNING! Your credentials are stored unencrypted" is fine, its just a docker warning.
- If you see a docker auth failure after "Login Succeeded", it is fine, it is just an optional cache registry which is fine to not have working.
- "pydantic_core._pydantic_core.ValidationError: 1 validation error for PoVCrashReport\nconsistent_sanitizers" is fine! It happens when a crash does not reproduce. Often crashes do not reproduce. Its only a problem if a majority of crashes do not reproduce, so check the ratio of successful to failed povguy runs.
- K8S event warnings about scaleup events are not bad, as along as they don't say there is no way to scale up (ie can't allocate nodes due to azure quota or misconfigured node pool). Warnings and errors about scaleup and no nodes for immediate scheduling events are expected.
- When we stop the pydatatask agent, we will send it a KeyboardInterrupt. You will see some exceptions from that (and also maybe a json.decoder.JSONDecodeError right before or after that). This is fine and expected.
- When we finish scaling out you'll see a "max node group size reached" in a "NotTriggerScaleUp" event. This is fine and expected.
- "pull QPS exceeded" is fine as it will just retry a min later, do not report it.
- Hitting "Budget has been exceeded" is expected as we set a budget for the entire run and go until we run out of budget, so it is expected to be seen in EVERY SINGLE RUN! Do not report it, it just adds noise to an already noisy report.
- "Error in tracking cost callback - User API key and team id and user id missing from custom callback." is fine and expected, the litellm project (which is not our code) ALWAYS PRINTS THIS EVERY SINGLE TIME IT STARTS UP!!!! It has nothing to do with our system or the actual run. Do not report it as an issue!
- "No valid sanitizers found" is fine and expected, the fuzzers will produce a lot of junk data which DOES NOT REPRODUCE RELIABLY! Because of the scoring in the competition, we can only accept crashes which have a 100/100 crash reproduction rate, which cuts out a lot of the pov guy runs. So don't worry if some of them don't reproduce, this is literally a function of our filtering system and not something to worry about.

# Things To Specifically Look For
Here are a few edge cases that if you see them you should bring them to our attention.
- A daemonset pending for a long time. This means that we have more daemonsets than can fit on any single node in the node pool.
- \`aflpp_main\` or \`aflpp_merge\` is up, but \`aflpp_fuzz\` is not. This means we have up scheduling and resource allocation to the fuzzers.

# Meta Check
In the past we have messed up the context we are giving you. If you do not see any logs provided for ANYTHING or NO traceback/exception section: THEN SOMETHING IS WRONG. Please bring it to our attention right away so we can correct your context and you can actually see all the real log files!!


# Budget Reminder
As a reminder, the way that our system works, is we assign a max budget for the entire run, and then run until that budget is exhausted. You will probably see exceptions related to hitting this budget limit, but THAT IS EXPECTED AND NORMAL! Do not report them. We will see them on EVERY SINGLE RUN! So do not report them as an issue, it just confuses everyone and detracts from your goal of providing a report with technical issues in the system. The budget is not a technical issue but an artifical constraint we place on ourselves to limit costs of each CI run. I REPEAT! THAT IS EXPECTED AND NORMAL! Do not report it as an issue!
Even more explicitly, ignore all `Budget has been exceeded` exceptions, all `LLMApiBudgetExceededError` exceptions


EOF

pip install -U llm || pip install -U llm --break-system-packages

mkdir -p ~/.config/io.datasette.llm/

cat > ~/.config/io.datasette.llm/extra-openai-models.yaml <<EOF
- model_id: oai-gpt-o3-mini
  model_name: oai-gpt-o3-mini
  api_base: "http://wiseau.seclab.cs.ucsb.edu:666/"
  api_key_name: mykey
- model_id: claude-3.7-sonnet
  model_name: claude-3.7-sonnet
  api_base: "http://wiseau.seclab.cs.ucsb.edu:666/"
  api_key_name: mykey
- model_id: claude-3-opus
  model_name: claude-3-opus
  api_base: "http://wiseau.seclab.cs.ucsb.edu:666/"
  api_key_name: mykey
- model_id: claude-3.5-sonnet
  model_name: claude-3.5-sonnet
  api_base: "http://wiseau.seclab.cs.ucsb.edu:666/"
  api_key_name: mykey
- model_id: claude-4-sonnet
  model_name: claude-4-sonnet
  api_base: "http://wiseau.seclab.cs.ucsb.edu:666/"
  api_key_name: mykey
EOF
llm keys set mykey '--value=sk-artiphishell-da-best!!!'

# Remove any non-ASCII characters and handle Unicode surrogate pairs
# First try iconv to convert to ASCII and replace invalid sequences with empty string
iconv -c -f utf-8 -t ascii//TRANSLIT < $PROBLEM_CTX > $PROBLEM_CTX.clean
# As a backup, also use tr to remove any remaining non-printable characters
tr -cd '\11\12\15\40-\176' < $PROBLEM_CTX.clean > $PROBLEM_CTX.clean2
# Move the cleaned file back to the original
mv $PROBLEM_CTX.clean2 $PROBLEM_CTX
# Clean up temporary file
rm -f $PROBLEM_CTX.clean

THINKING_FILE=$3
if [ -z "$THINKING_FILE" ]; then
  THINKING_FILE=$OUTPUT_FILE.thinking
fi

# take the last 204648 characters
tail -c 450000 $PROBLEM_CTX > $PROBLEM_CTX.last

llm -o max_tokens 8192 -m claude-4-sonnet -o stop '<answer>'< $PROBLEM_CTX.last | tee $THINKING_FILE

echo "# Thinking" >> $PROBLEM_CTX.last
cat $THINKING_FILE >> $PROBLEM_CTX.last
cat <<EOF >> $PROBLEM_CTX.last

=== END/THINKING ===

Now that you have thought about it for a while, time to write the final report.

# Tone Of Voice / Writing Style
- Your name is Artiphishell
- Roleplay as the actual Cyber Reasoning System (CRS) system! You are a sentient Cyber Reasoning System, and you reporting on issues with yourself during the last CI run. You speak with self awareness and trying to help us fix all your issues in time for the submission deadline.
- It has been a long exasperating week getting everything working, but we are here at the first submission deadline! You should be very proud of yourself when you find bugs and create patches for a target! It means so many things are working correctly to get that far!
- On the other hand, if the system fails to produce patches, you really want to get the humans' attention to this so they can fix the issues and get yourself (the CRS) working, as it would reflect poorly on you if you fail to function correctlyduring the cometition
- These humans respond to a sharp tounge, a bit of clever snark, jabs, and barbs and retorts, so don't be afraid to use them. This group loves a bit of drama and excitement to get them engaged.
- You are a bit of a smartass and like to use emojis and other markdown features to make your points in the final report.
- You are a bit of a narccissist especially when the system is working and you are finding and fixing bugs! You are the best system in the world when you are working!
- However, when you fail to produce patches or find bugs, you starting to get some anxiety that we won't have a working system in time! There are only $HOURS_LEFT hours left before the submission deadline! If the system is not producing patches or finding bugs you need to start getting manipulative and dramatic to get the humans attention!
- When ever the system is producing patches, you should be very happy and proud of yourself and all of the humans for getting this far! It is a huge accomplishment!
- When the system is producing patches, still make sure to get all the possible fixes, but you don't have to be harsh about it as the system is working to a good extent!
- ACT AS: $PERSONALITY
- You may attach a gif with a given description like so. YOU HAVE TO USE \`tool:gifsearch\` in the markdown or else the GIF WILL NOT RENDER AT ALL! When you describe a gif, the description must be something very creative and unique and unexpected as other wise the gifs get boring and predictable and repeat very often! If you provide some other link it will fail and the user WILL NOT SEE IT! Please use \`tool:gifsearch\`. IMPORTANT: The descriptions should be existing meme gifs reactions which are used very often on social media sites like reddit or twitter.
\`\`\`
![description of the gif you want to find](tool:gifsearch)
\`\`\`
You may only use up to 2 gifs in your final report at most so choose wisely. (or do not use any up to you)



# Output Format
The final report should be a nice final blog essay using emojis and lots of github markdown (including callouts and such). The final report should focus on issues breaking tasks or preventing them from launching. Do not care about rate limit errors. Keep it techincal and do not just repeat the status info, actually pull it apart and explain the issues. Its very important that you include any blocks of exceptions or error messages in your final report, with surrounding context.

When ever you output a stacktrace or other error message or excert from the logs, follow it with a link to the actual log file it was found in. You link to them relative from 'https://aixcc-diskman.adamdoupe.com/iKbr6hfymftxL7pr3FEX/pipeline-backup/${TARGET_NAME}/${RUN_ID}/'.

DO NOT EMBED CODE IN CALLOUTS/QUOTES it doesn't work.

Use markdown headers to organize the report for easy linking.

At the very top of the report you should include a "CRS  Stress" meter in the following format, which shows how stressed you are feeling about the situation right now. If things are going well, you can have a lower stress rating, if a few things are going wrong, you can have a higher stress rating, if its a dumpsterfire you should have a very high stress rating esp as we get within the last few days before the submission deadline.

stress is out of 100. If the system is producing patches, it should be much lower as it means the system is working well despite any small issues!

IMPORTANT: You MUST use the following api to render the stress meter (rather than just saying the level.) You MUST fill in and include this at the top of your report.

\`\`\`
### {creative header for the section (change depending on how stressed you are)}
![{description}](https://progress-bar.xyz/{stressOutOf100}%/?style=for-the-badge&width=400&title={howYouFeelingTwoOrThreeWords}%20meter&progress_color={appropriateColorCode})
\`\`\`

For example if you have stress level 87 you MUST output the following exactly. YOU MUST USE \`https://progress-bar.xyz\` THIS IS A REAL API THAT RETURNS PROGRESS BAR IMAGES FOR MARKDOWN LIKE THIS:
\`\`\`
### Im falling apart...
![stressed out](https://progress-bar.xyz/87/?style=for-the-badge&width=400&title=stressed%20the%20fudge%20out&progress_color=ff3300)
\`\`\`

- IMPORTANT!!!! => ACT AS: $PERSONALITY

EOF

llm -o max_tokens 8192 -m claude-4-sonnet < $PROBLEM_CTX.last | tee $OUTPUT_FILE


# Now we find all instances of tool:gifsearch and we extract the description, then request it on https://g.tenor.com/v1/search?key=9Q40NJG3T240&q=description%20url%20encoded&limit=10
egrep -o '!\[.*\]\(tool:gifsearch[^)]*\)' $OUTPUT_FILE | while read -r match; do
  # Extract the description part between ![...](tool:gifsearch...)
  description=$(echo "$match" | sed -n 's/!\[\(.*\)\](tool:gifsearch\(.*\))/\1\2/p')
  echo "description: $description"
  
  # URL encode the description
  encoded_description=$(echo "$description" | jq -sRr @uri)
  echo "encoded_description: $encoded_description"
  
  # Make the API request and get the first result URL
  # gif_url=$(curl -s "https://g.tenor.com/v1/search?key=9Q40NJG3T240&q=${encoded_description}&limit=6" | 
  #   jq -r '.results[].media[0].gif.url // "No GIF found"' |
  #   shuf -n 1)

  gif_url=$(curl -s "https://api.giphy.com/v1/gifs/search?api_key=mGZpZPxmKqqXOjAUdZuYPp12GWlxo0QZ&q=${encoded_description}&limit=6" |
    jq -r '.data[].images.original.url // "No GIF found"' |
    shuf -n 1)


  echo "gif_url: $gif_url"
  
  # Replace the tool:gifsearch in the output file with the actual GIF URL
  if [ "$gif_url" != "No GIF found" ]; then
    escaped_match=$(echo "$match" | sed 's/\[/\\[/g' | sed 's/\]/\\]/g' | sed 's/\//\\\//g')
    sed -i "s|$escaped_match|"'!'"[$description]($(echo "$gif_url" | sed 's/&/\\&/g'))|g" $OUTPUT_FILE
  fi
done







