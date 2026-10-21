#!/bin/bash
# Jamf Pro extension attribute: "<version> <enrolled|not-enrolled>" or "not installed".
P=/opt/prismor/bin/prismor
if [ ! -x "$P" ] || [ ! -f "/Library/Application Support/Prismor/system.json" ]; then
  echo "<result>not installed</result>"; exit 0
fi
v=$(PRISMOR_NO_UPDATE_CHECK=1 "$P" --version 2>/dev/null | awk '{print $2}')
if PRISMOR_NO_UPDATE_CHECK=1 "$P" enroll-status >/dev/null 2>&1; then e=enrolled; else e=not-enrolled; fi
echo "<result>$v $e</result>"
