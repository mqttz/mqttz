## Implement Full Loop

### Call to the TA
1. Intercept the message right before it is being sent to the client at: `src/subs.c`
2. Grep the client ID from the subscriber identifier.
3. Unwrap
4. Reencrypt
5. Wrap again

### Map subscribers to MQT-TZ Cli Ids
1. Maybe do so at: `src/handle_subscribe.c`
2. How to store these?
    - For the moment we store a file with:
        - File name: mqtt cli_id
        - File content: mqt-tz cli_id
