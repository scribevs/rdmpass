<p align="center">
  <img src="assets/logo.png" alt="rdmpass logo" width="200"/>
</p>

# rdmpass

**True random password generator using mouse movement entropy with extensive customization options.**

---

## Features
- **True randomness** collected from real-time mouse movement patterns.
- **256-bit entropy** hashed with SHA-256.
- **Fully customizable**:
  - Password length
  - Minimum mouse movements before generation
  - Character sets: lowercase, uppercase, numbers, symbols, extended Latin, or custom
  - Option to require at least one character from each selected set
- **Local-only generation** — no data leaves your browser.
- Built with a Node.js backend and React frontend.

---

## Why Mouse Movement?
Most password generators rely on pseudo-random number generators (PRNGs), which, while strong, are ultimately deterministic algorithms seeded from predictable sources like the system clock or OS entropy pools.  

By contrast, **mouse movement entropy** is:
- **Unpredictable** — small variations in human motion, speed, and direction are extremely hard to model or guess.
- **High-entropy** — every recorded movement (position + timestamp) adds more unpredictability to the entropy pool.
- **Local and private** — all data is processed in your browser and never transmitted.

The result is a truly unique 256-bit key that is statistically infeasible to reproduce.

---

## How It Works
1. **Collect entropy** — browser captures mouse coordinates and timestamps until the target movement count is reached.
2. **Hash** — captured data is SHA-256 hashed into a 256-bit key.
3. **Generate** — password is derived securely from the key using the chosen character sets.
4. **Display** — generated password appears with a copy-to-clipboard option.

---

## Installation

### Prerequisites
- [Node.js](https://nodejs.org/) v16 or newer

### Steps
```bash
# Clone the repository
git clone https://github.com/scribevs/rdmpass.git
cd rdmpass

# Start the server
node server.js
```
Then open:
```
http://localhost:3000
```

---

## Usage
1. Open the app in your browser.
2. Adjust settings (length, movement count, character sets).
3. Move your mouse until the progress bar fills.
4. Click **Generate Password**.
5. Copy your password if desired.

---

## Security Notes
- All randomness and password generation happen **entirely in the browser**.
- For maximum strength, increase the mouse movement count and select multiple character sets.

---

## License

