#!/bin/bash

set -e

function emojify() {
    if [ -z "$1" ]; then
        echo "❌ (null)"
    else
        echo "$@" | sed -e 's/true/✅ (true)/g' -e 's/false/❌ (false)/g'
    fi
}

# ==== DISPLAY CONFIGURATION ====
echo ""
echo "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣦⡶⠶⠖⠖⠒⠢⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⡿⠟⢋⣡⣤⣴⡶⠾⠻⠛⠛⡛⡙⡑⠒⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠚⢛⢋⠃⣀⡋⣙⣩⣉⣁⣀⡈⢚⢙⠛⠟⠛⢛⣙⣙⣍⣂⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀   ⠀⠀⠀⠀⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣴⡄⣶⣿⣿⣿⣿⠸⣿⡗⢸⣿⠟⢻⣿⡅⢿⣿⠀⠀⣷⡦⢠⣬⡉⣉⡉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  ⠀⠀⡀⣴⣿⠟⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⡇⢸⣿⠋⢻⣿⠆⠈⠨⣿⡇⠁⢑⣿⣏⢸⣿⠇⢸⣿⠆⣻⣿⠀⠀⣿⡯⢸⣿⡇⢽⣿⠿⣷⢰⣦⡄⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⡇⣻⠃⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⣿⡿⢿⣿⡇⢸⣿⢄⢸⣿⡃⠀⠨⣿⡇⠀⢐⣿⡧⢸⣿⣇⣼⣿⡃⣽⣿⠀⠀⣿⡯⢸⣿⡃⣽⣿⡀⡀⢸⣿⡇⢘⣿⡇⣶⣦⢤⡄⢀⣤⡂⠀⢘⣿⡇⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠠⠻⠻⠻⣋⣄⣸⣿⡇⢸⣿⣿⡟⠛⠁⠀⠨⣿⡇⠀⢐⣿⡗⢸⣿⠟⠋⠛⠁⣾⣿⣶⣿⣿⡯⢸⣿⠇⣽⣿⣿⣿⢸⣿⣷⣾⣿⡇⣿⣿⣶⡆⢸⣿⡅⠀⢸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢿⣿⠿⢿⣿⡇⢸⣿⣿⣷⡄⠀⠀⠨⣿⡇⠀⢐⣿⣏⢸⣿⠇⠀⠀⠀⣽⣿⠀⠀⣿⡯⢸⣿⠇⠀⠀⣿⣿⢸⣿⡇⢨⣿⡇⣿⣿⣤⡆⠸⣿⣦⣀⢸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⢿⡇⢸⣿⡘⢿⣷⡀⠀⠨⣿⡇⠀⢐⣿⡧⢸⣿⠇⠀⠀⠀⣽⣿⠀⠀⣿⡯⢸⣿⠇⠀⣀⣿⣿⢸⣿⠇⠨⠿⠃⠙⠁⠁⠀⠀⠀⠉⠛⠸⣿⣿⣶⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠋⠂⠈⠿⢷⡀⠨⣿⡇⠀⢐⣿⡗⢸⣿⠇⠀⠀⠀⣽⣿⠀⠀⣿⡯⠸⡿⠇⠻⠛⠋⠋⠈⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  ⠀⠉⠻⢿⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢳⣶⣆⠡⣥⣤⡀⢍⣍⣈⠋⠁⠀⠀⠀⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀     ⠀⠀⠀⠀⠀⠈⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠓⠊⠙⠻⠦⡝⡛⠷⣦⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"
echo "┌───────────────────────────────────────────────────────────────────────────┐"
printf "│            %40s                       │\n" "DEPLOYMENT $DEPLOYMENT_NAME CONFIGURATION"
echo "├───────────────────────────────────────────────────────────────────────────┤"
printf "│ %-36s │ %-36s │\n" "🤹 NUM_CONCURRENT_TASKS" "$NUM_CONCURRENT_TASKS"
printf "│ %-35s │ %-36s │\n" "⭕ FULL_MODE_TASKS" "$FULL_MODE_TASKS"
printf "│ %-35s │ %-36s │\n" "⏳ FULL_MODE_TASK_LENGTH_MINUTES" "$FULL_MODE_TASK_LENGTH_MINUTES"
printf "│ %-36s │ %-36s │\n" "🔺 DELTA_MODE_TASKS" "$DELTA_MODE_TASKS"
printf "│ %-35s │ %-36s │\n" "⌛ DELTA_MODE_TASK_LENGTH_MINUTES" "$DELTA_MODE_TASK_LENGTH_MINUTES"
echo "├───────────────────────────────────────────────────────────────────────────┤"
printf "│ %-33s │ %-41s │\n" "❄️ OPENAI_BUDGET" "$OPENAI_BUDGET"
printf "│ %-34s │ %-41s │\n" "🅰️ CLAUDE_BUDGET" "$CLAUDE_BUDGET"
printf "│ %-31s │ %-41s │\n" "💎 GEMINI_BUDGET" "$GEMINI_BUDGET"
printf "│ %-31s │ %-41s │\n" "💰 GRAMMAR_BUDGET" "$GRAMMAR_BUDGET"
printf "│ %-31s │ %-41s │\n" "🩹 PATCHING_BUDGET" "$PATCHING_BUDGET"
printf "│ %-33s │ %-41s │\n" "⏲️  ROLLING_PERIOD_MINUTES" "$ROLLING_PERIOD_MINUTES"

echo "├───────────────────────────────────────────────────────────────────────────┤"
printf "│ %-31s │ %-41s │\n" "🪛 MAX_USER_NODES" "$MAX_USER_NODES"
printf "│ %-31s │ %-41s │\n" "🪛 USER_VM_SIZE" "$USER_VM_SIZE"
printf "│ %-31s │ %-41s │\n" "🌵 MAX_FUZZER_NODES" "$MAX_FUZZER_NODES"
printf "│ %-31s │ %-41s │\n" "🌵 MAX_FUZZER_NODES_LF" "$MAX_FUZZER_NODES_LF"
printf "│ %-31s │ %-41s │\n" "🌵 FUZZER_VM_SIZE" "$FUZZER_VM_SIZE"
printf "│ %-31s │ %-41s │\n" "🌵 FUZZER_VM_SIZE_LF" "$FUZZER_VM_SIZE_LF"
printf "│ %-31s │ %-41s │\n" "🩹 MAX_PATCHER_NODES" "$MAX_PATCHER_NODES"
printf "│ %-31s │ %-41s │\n" "🩹 PATCHER_VM_SIZE" "$PATCHER_VM_SIZE"
printf "│ %-34s │ %-41s │\n" "🗺️ MAX_COVERAGE_NODES" "$MAX_COVERAGE_NODES"
printf "│ %-34s │ %-41s │\n" "🗺️ COVERAGE_VM_SIZE" "$COVERAGE_VM_SIZE"
printf "│ %-31s │ %-41s │\n" "🐕 MAX_SERVICE_NODES" "$MAX_SERVICE_NODES"
printf "│ %-31s │ %-41s │\n" "🐕 SERVICE_VM_SIZE" "$SERVICE_VM_SIZE"
printf "│ %-31s │ %-41s │\n" "👑 CRITICAL_VM_SIZE" "$CRITICAL_VM_SIZE"
printf "│ %-31s │ %-41s │\n" "💽 VM_DISK_SIZE" "$VM_DISK_SIZE"


echo "├───────────────────────────────────────────────────────────────────────────┤"
printf "│ %-31s │ %-42s │\n" "🌐 NO_EXTERNAL_REGISTRY" "$(emojify $NO_EXTERNAL_REGISTRY)"
printf "│ %-31s │ %-42s │\n" "🌐 NO_PUBLIC_IP" "$(emojify $NO_PUBLIC_IP)"
printf "│ %-31s │ %-42s │\n" "🔑 EXCLUDE_GITHUB_CREDENTIALS" "$(emojify $EXCLUDE_GITHUB_CREDENTIALS)"
printf "│ %-31s │ %-42s │\n" "🤖 USE_CLUSTER_LITELLM" "$(emojify $USE_CLUSTER_LITELLM)"
printf "│ %-31s │ %-42s │\n" "🧪 INCLUDE_CI_PODS" "$(emojify $INCLUDE_CI_PODS)"
printf "│ %-31s │ %-42s │\n" "🧪 INCLUDE_NODE_VIZ" "$(emojify $INCLUDE_NODE_VIZ)"
printf "│ %-31s │ %-42s │\n" "🛜  USE_TAILSCALE" "$(emojify $USE_TAILSCALE)"

echo "├───────────────────────────────────────────────────────────────────────────┤"
printf "│ %-31s │ %-42s │\n" "💾 ENABLE_IN_RUN_BACKUP" "$(emojify $ARTIPHISHELL_GLOBAL_ENV_ENABLE_IN_RUN_BACKUP)"
printf "│ %-38s │ %-42s │\n" "🐦‍🔥 DELETE_ON_CANCEL" "$(emojify $ARTIPHISHELL_GLOBAL_ENV_DELETE_ON_CANCEL)"
echo "├───────────────────────────────────────────────────────────────────────────┤"
printf "│ %-29s │ %-41s │\n" "GITHUB_REF" "$GITHUB_REF"
printf "│ %-29s │ %-41s │\n" "CRS_API_URL" "$CRS_API_URL"
printf "│ %-29s │ %-41s │\n" "COMPETITION_API_URL" "$COMPETITION_API_URL"
echo "└───────────────────────────────────────────────────────────────────────────┘"
echo ""



