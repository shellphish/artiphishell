NUM_INSTANCES=10
TIMEOUT=24h

# function to run the setup for an ablation experiment (tmux session)
function ablation_setup() {
    # create a new tmux session
    tmux new-session -d -s "$EXPERIMENT_NAME"
}

function ablation_run_variant() {
    variant_name=$1
    instances=$((NUM_INSTANCES - 1))
    # decrement instances by 1 to get the last instance number
    shift 1

    cargo build --release --bin symcts "$@"
    sleep 2
    for n in $(seq 0 $instances); do
        NAME="${variant_name}_${n}"
        SYNC_DIR="./ablation_sync_${EXPERIMENT_NAME}/${NAME}/"
        tmux new-window -t "$EXPERIMENT_NAME": -n "$NAME"
        tmux send-keys -t "${EXPERIMENT_NAME}:${NAME}" "RUST_LOG=generate_mutations_sampled=DEBUG,symcts_scheduler=DEBUG,sync_from_afl_stage=INFO timeout $TIMEOUT ./target/release/symcts -i ./corpus -s '$SYNC_DIR' -n '$NAME' -c ./harness_symcts_afl++ -- ./target_symcts" C-m
    done
}