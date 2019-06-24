### Pre-Conditions
+ Server has a valid certificate emitted by Let's Encrypt
+ Server has a Public Key available to all clients, w/ the private counterpart in Secure Storage.
+ Server has a listener on `key_query` topic.

### Publish
1. Publisher has agreed on S. Key w/ Server?
    + Y: Publish over TLS w/ App Data following this scheme:
        {client_id: <CLI_ID>, payload: ENC w/ SKey}
    + N: Publish over rr (TLS) to `key_query` topic.
        - Send S. Key Proposal encrypted with Public Key
        - Await for response at `key_response` topic.
        - Should receive the following message: 
            {client_id: <CLI_ID_SUGG_BY_SERVER>, payload: OK, encrypted with SKey}
2. Back to 1

### Subscribe
1. Publisher has agreed on S. Key w/ Server?
    + N: Go-To Publish
    + Y: Subscribe normally TODO: how does he pass the client id?
