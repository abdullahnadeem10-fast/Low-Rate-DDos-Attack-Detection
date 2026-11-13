#!/bin/sh
# Fixed bounded CGI read target. Complete POST probes validate it before attacks.
# Apache's existing request-read timeout module remains enabled and unchanged.
case "$CONTENT_LENGTH" in ''|*[!0-9]*) exit 1;; esac
if [ "$CONTENT_LENGTH" -gt 65536 ]; then exit 1; fi
received=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null | wc -c)
if [ "$received" -ne "$CONTENT_LENGTH" ]; then printf 'Status: 400 Bad Request\r\n'; fi
printf 'Content-Type: text/plain\r\nContent-Length: 3\r\n\r\nok\n'
