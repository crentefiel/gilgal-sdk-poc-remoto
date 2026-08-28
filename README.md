# gilgal-sdk-poc-remoto

Experimental repository for `H-GILGAL-SDK-01` remote enforcement PoC.

- `main` = STABLE (protected branch, required status check `gilgal-gate`).
- Candidate changes arrive via PR from candidate branches.
- `.gilgal/verify-remote.js` recomputes the gate from Git ground truth (never trusts a stored `GATE=PASS`).
- Human Decision is verified against `.gilgal/keys/human.pub` (STABLE baseline). Private key is held out-of-band by a human (not in this repo, not readable by the agent).

This repo is a throwaway test fixture. Do not use for production.
