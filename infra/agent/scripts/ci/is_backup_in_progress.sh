#!/bin/bash

if [ -f /tmp/.backup_in_progress ]; then
  echo RUNNING
else
  echo BACKUPDONE
fi