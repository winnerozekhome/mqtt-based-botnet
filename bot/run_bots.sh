#!/bin/bash

# Check if the number of instances (X) is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <number_of_instances>"
  exit 1
fi

# Get the number of instances from the first argument
NUM_INSTANCES=$1

# Function to run the Python script
run_instance() {
  INSTANCE_NUM=$1
  echo "Starting instance $INSTANCE_NUM"
  python3 main.py --instance "$INSTANCE_NUM" &
}

# Run X instances in parallel
for i in $(seq 1 "$NUM_INSTANCES"); do
  run_instance "$i"
done

# Wait for all background jobs to finish
wait
