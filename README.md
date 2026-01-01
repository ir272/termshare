# termshare

![Rust](https://img.shields.io/badge/Rust-000000?style=flat&logo=rust&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

A simple CLI tool to share your terminal session over the web.

https://github.com/user-attachments/assets/9369c647-bf03-4ae7-a2ef-6824f6f0ac5e

```bash
# Install
git clone https://github.com/ir272/termshare.git
cd termshare
cargo install --path .

# Share locally
termshare

# Share over the internet
termshare --public
```

This starts a web server and gives you a URL. Anyone with the link can watch your terminal live (unless there's a password or maximum viewer count).

**Options:**
- `--password` - Require password to view
- `--allow-input` - Let viewers type in your terminal
- `--public` - Share over the internet via Cloudflare Tunnel
- `-c <cmd>` - Run a specific command instead of shell
- `--max-viewers <n>` - Limit concurrent viewers
- `--expose` - Expose to local network
- `-p <port>` - Set port (default: 3001)

![password-required](docs/password-required.png)
![session-full](docs/session-full.png)
![disconnected](docs/disconnected.png)

```bash
**Example**

# Password protected with viewer input
termshare --public --password --allow-input

#Then in the shared terminal:
cd ~/projects/project-name
npm run dev
# Ctrl+C to stop npm (session stays alive)

# Start sharing specific commands!
git status
git commit
# etc...
```

Press `Ctrl+Q` to exit.

## Acknowledgements

Built by [@iroyballer](https://x.com/iroyballer)
