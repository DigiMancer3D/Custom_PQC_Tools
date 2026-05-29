# Custom PQC Key Tools (Updated Version)

These are three small C programs that work together to create and use post-quantum keys plus Bitcoin styled keys. This is a completely custom setup and is not intended to be used with keys that contain real value, wealth or have the potential to do so. 

## 1. pqc_keygen_new.c, How keys are made

This program builds one master keychain file (`.kchain`).

### Step-by-Step

1. **Start seed**  
   Take 64 random bytes → turn into 512 trits (digits 0,1,2):  
   `trits[i] = '0' + (random_byte % 3)`  
   Entropy: 512 × log₂(3) ≈ 811 bits.

2. **Expand**  
   Repeat rolling into ternary until >10,000 trits:  
   - `ternary_d_shift(current)`:  
     ```
     result[0] = current[0]
     for i ≥ 1:
         prev = current[i-1] - '0'   # 0,1, or 2
         nxt  = current[i]   - '0'
         if prev == nxt:
             '0'
         else if prev > nxt:
             '1'
         else:
             '2'
     ```  
     Example: `"012021"` → `"022121"`

   - `full_pass(current, prev)` does:  
     Split into three equal parts A,B,C.  
     Shift each → newA, newB, newC.  
     `jump[i] = ((a ^ b) + (c ^ b)) % 3`  
     Mix with XOR and add from previous round, all mod 3.  
     Then run **SPX-QEC cleanup** up to 20 times:  
     Remove these exact patterns (and their reverses + joins):  
     `"00"`, `"11"`, `"01"`, `"10"`, `"100"`, `"011"`, `"101"`, `"010"`, `"1001"`, `"0110"`, `"10100"`, `"01011"`, `"001101"`.  
     (Like error-correcting by deleting known bad strings.)

3. **Reduce**  
   Run `ternary_d_shift` 8 times, then fold:  
   `folded[i] = ((current[idx1] ^ current[idx2]) % 3)`  
   → exactly 6000 trits.

4. **Final pool**  
   SHAKE-256(6000 trits) → 512-byte master pool.  
   All later keys pull randomness from this pool (`custom_randombytes`).

5. **Generate keys**  
   - Master: Falcon-512, ML-DSA-65 (Dilithium3), SLH-DSA-SHA2-128s (SPHINCS+), hybrid SPHINCS+.  
   - 9 roles (0-8): same four PQC keys each + one secp256k1 Bitcoin key (role 0 uses direct pool, others SHAKE-seeded by role number).  
   Save everything as hex strings in JSON: `../svc-wallet/pqc_master_YYYYMMDD_HHMMSS.kchain`

**What you see when it finishes**  
- Progress lines (seed length, expansion length, etc.)  
- Final file with all secret/public keys in hex  
- You can open the `.kchain` in any text editor, it is just clean JSON.

**Check keys work**  
After generation, a simple checker reads the `.kchain`, pulls Falcon and Dilithium keys for master + roles 0/1/5/6/7, signs a test message, verifies it, and prints PASS or FAIL. Use it any time you want to confirm a keychain is good.

## 2. pqc_hybrid_signer.c, How signing works

Run it like:  
`./pqc_hybrid_signer mykeychain.kchain 3 "Hello world" [--base64]`

### Steps

1. **Load**  
   Open `.kchain`, find role 3 → get its SPHINCS+ secret key + Bitcoin private key.

2. **Bitcoin part (standard ECDSA)**  
   - Make WIF (base58) and `pkh(WIF)` descriptor.  
   - Sign:  
     Bitcoin message hash = SHA256(SHA256( `0x18"Bitcoin Signed Message:\n" + 1-byte-length + message` ))  
     Produce **65-byte compact signature** (recovery ID 27-30, low-S normalized, r + s).

3. **PQC part (the quantum-resistant wrapper)**  
   - State = SHA3-256( Bitcoin-signature + original message ) → 32 bytes.  
   - Turn into 512 trits: `trits[i] = '0' + (state[i % 32] % 3)`  
   - Run same **SPX-QEC cleanup** (remove the 13 patterns, up to 20 passes).  
   - Sign the cleaned trit string with SLH-DSA (SPHINCS+) using the role’s hybrid secret key.  
     This is exactly what a normal PQC signer does:  
     `OQS_SIG_sign(algo, signature, &len, message, msg_len, secret_key)`  
     but here the “message” is the cleaned trits instead of raw bytes.

4. **Combine & output**  
   Blob = Bitcoin-sig (65 B) + SPHINCS+-sig + 32 bytes of `0xAA`  
   → base58 encode → “faux signature” (long readable string).  
   Also saves a `.msg` JSON file with everything (signature, WIF, descriptor, timestamp) in `../svc-wallet/`.

**How is this hybrid?**  
- Inner Bitcoin signature can be verified with common processes.  
- Outer SPHINCS+ signature (on a distilled hash of the above) should have quantum resistance.  
- A pure PQC signer would skip step 2 and just call `OQS_SIG_sign` directly on the original message.  
  Here we keep old signing compatibility as the first layer and add the post-quantum layer on top.

**Outputs you see**  
```
✅ BTC WIF: ...
✅ Descriptor: pkh(...)
✅ Hybrid SPHINCS+BTC Signature (faux base58): ...
✅ Signed message saved to: ..._pqc-signed_....msg
```
(If you add `--base64` you also get the plain base64 signature.)

## 3. How the programs work together

1. Run `pqc_keygen_new.c` once → get a fresh `.kchain` file.  
2. (Optional) Run the checker on that file to confirm all keys sign/verify.  
3. Run `pqc_hybrid_signer.c` many times with the same `.kchain` + different roles + different messages → each time you get:  
   - Verifiable Bitcoin signature  
   - Quantum-resistant wrapper  
   - `.msg` JSON archive  
   - Ready-to-use descriptor for wallets.

 
Generate keys → validate if you want → sign messages.  
Everything stays in the `svc-wallet/` folder. No extra setup just simple maths (mod-3 shifts, pattern removal, standard liboqs calls) and two small programs that talk to each other through the `.kchain` JSON.

Copy the files, compile with the usual `liboqs` + OpenSSL + jansson, and you’re ready to test with PQC keys that can be generated on most hardware that is capable of being a bitcoin node.

----

This is for showcasing further uses of my custom seeding, there is a [simplier version of these same tools](https://github.com/DigiMancer3D/PQC_key_tools). I used BTC (double-sha+base58) private key as an entropy inclusion because I use this for something on my own that uses keys that are similar but not compatable with BTC. BTC or Bitcoin was used in the original build because I did not have a working version of my double-shake+base58 at the time (I do now). Compile with liboqs + jansson + OpenSSL, run, and you have working example of potential post-quantum keys and signatures in minutes. This shows how there are processes that can work on smaller form factor machine and older hardware that can use any data to start the seeding and if we ran through this entire setup again, taking our output as input; we could potentially decouple the entire input->seed process.

This is not intended for direct use with bitcoin and real cryptographic keys that hold wealth, value or have the potential to do so until you have fully tested and verified you feel comfortable with this system & setup. This is 100% custom designed processing for a different project but seem notable in how the whole process worked I felt the need to create a repo just for it.

---
