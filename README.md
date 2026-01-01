# termshare

A simple CLI tool to share your terminal session over the web.

Demo Vid:

```bash
# Install
git clone https://github.com/ir272/termshare.git
cd termshare
cargo install --path .

# Share your terminal from another project
termshare -c "cd ~/projects/my-app && npm run dev"

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

```bash
# Password protected with viewer input
termshare --public --password --allow-input

# Run a specific command
termshare -c "htop"
```

Press `Ctrl+Q` to exit.

## Acknowledgements

Built by [@iroyballer](https://x.com/iroyballer)
