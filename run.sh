#!/bin/bash
while true; do
  sudo ./backend/b23_broker 80 2>&1 | tee -a b23wtf.log
done
