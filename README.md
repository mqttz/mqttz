### MQT-TZ: Running mosquitto in the TrustZone

#### To-Do List:

**Implementation:**
1. Client:
    1. Key Exchange: support asymmetric encryption.
2. Broker:
    1. Key Exchange: filter `id_query` topics
    2. Locate where to do the reencryption
    3. Reencryption TA: key retrieval from persistent storage working.
3. Deployment:
    1. Run custom implementation in Buildroot

**Evaluation:**
1. Make artificial ECG generator.
2. Microbenchmarks:
    1. TrustZone Reencryption:
        + How many bytes/second can we reencrypt in the SW and how does it compare to the Normal World?



**Dissemination:**
1. 15/08/19 - SysTEX
2. 06/09/19 - Middleware (Industrial Track)
