/goal Add the first real ios-research research module for audio processing.

Focus on authorized security research against controlled audio-processing targets.

Support formats where practical:

    WAV
    MP3
    AAC
    ALAC

Implement:

    ios-research target audio list
    ios-research target audio inspect
    ios-research fuzz --target audio:<format>

Add format-aware mutation strategies.

Track:

    accepted
    rejected
    timeout
    crash
    abnormal termination

Create normalized crash artifacts containing:
- Input
- SHA-256
- Target
- Format
- Mutation lineage
- Timestamp
- Process information
- Diagnostics

Implement crash deduplication.

Do not implement:
- Permission bypass
- Microphone activation
- Camera activation
- Persistence
- Sandbox escape
- TCC bypass
- Exploit chains

Provide mock targets so the module can run in CI.

Document how an authorized research device can be connected later.

Run all tests before completing the phase.
