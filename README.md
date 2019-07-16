### MQT-TZ: Running mosquitto in the TrustZone

#### To-Do List:

**Implementation:**
1. Client:
    1. Key Exchange
        1. Support Asymmetric Encryption.
2. Broker:
    1. Key Exchange
        1. Filter `id_query` Topics
        2. Support Asymmetric Encryption
    2. Payload Reencryption
        1. Key Retrieval from Persistent Storage Working.
3. Deployment:
    1. Run custom `mosquitto` implementation in Buildroot
    2. Move everything to my personal laptop

**Evaluation:**
1. Make artificial ECG generator.
2. Microbenchmarks:
    1. P1: TrustZone Reencryption:
        + How many bytes/second can we reencrypt in the SW and how does it compare to the Normal World?
        + Measure:
            + Time to retrieve decrypt Key from Secure Storage
            + Time to decrypt payload
            + Time to retrieve encrypt key from Secure Storage
            + Time to encrypt payload
        + Vary:
            + Run in NW vs SW
            + Payload Size of 1kB, 4kB, 8kB, 16kB
        + Plot Structure:
            + ![Fig 14 in "On the Performance of ARM TrustZone"](./img/trustzone-comparison.png)

**Figures:**

**Dissemination:**
1. 15/08/19 - SysTEX
2. 06/09/19 - Middleware (Industrial Track)
