# Hart's Anti-Venom Desktop Guard (Windows)

Zero-telemetry, client-side Windows desktop defense against EVM address poisoning, zero-value ERC-20 transfer pollution, and vanity collision traps—built on Tauri v2 and Microsoft Edge WebView2.

## 5-Layer Defense Architecture

1. **Inbound Dust & Zero-Value Log Scrubbing:** Filters deceptive zero-value `Transfer` events and micro-dust logs before interface rendering.
2. **Outbound Signature & History Pairing:** Separates user-signed outbound counterparties from unsolicited inbound burner pollution.
3. **Anti-Vanity Visual Hashing & Middle-Hex Focus:** Dims easily spoofed outer hex boundaries, highlights center hex characters, and renders a deterministic 5-block Keccak-256 color hash.
4. **Tamper-Evident Local Keystore:** Protects whitelisted counterparties using AES-256-GCM backed by the Windows Credential Manager (`wincred`).
5. **Pre-Flight Nonce & Topology Oracle:** Flags zero-nonce EOAs sharing boundary characters with known contacts.

## Legal & Links

- License: [Apache 2.0](LICENSE)
- Privacy Policy: [PRIVACY.md](PRIVACY.md) | [hartsantivenom.com/privacy](https://hartsantivenom.com/privacy)
- Terms of Service: [TERMS.md](TERMS.md)
- Official Portal: [hartsantivenom.com](https://hartsantivenom.com)
- Support: [x401.tech@gmail.com](mailto:x401.tech@gmail.com)