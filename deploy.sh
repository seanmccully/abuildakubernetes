#!/usr/bin/env bash
#
# Run the deployments

# Ensure logs directory exists
mkdir -p logs

# Execute the main process script, passing through any arguments
./proc.sh "$@" 2> logs/proc.err 1> logs/proc.out

# Check the exit status
if [ $? -ne 0 ]; then
  echo "Deployment failed. Check logs/proc.err for details."
  exit 1
else
  echo "Deployment finished successfully."
fi
