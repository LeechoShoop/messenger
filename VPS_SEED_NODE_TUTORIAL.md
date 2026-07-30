# 🚀 How to Setup a Primus Seed Node on a VPS (For Beginners)

This guide will show you exactly how to host your own Primus seed node on a Virtual Private Server (VPS) step-by-step. Even if you've never used a Linux server before, you will be able to do this!

---

## Step 1: Get a VPS (Virtual Private Server)

You need a server that is always online and has a public IP address. You can rent a very cheap one (e.g., $4-$5/month) from providers like **DigitalOcean**, **Hetzner**, **Linode**, or **Vultr**.
- **OS**: Choose **Ubuntu 22.04** or **Ubuntu 24.04**.
- **Specs**: The cheapest tier (1 CPU, 1GB RAM) is more than enough!

Once your server is created, the provider will give you an **IP Address** and a **Password** (or SSH key).

## Step 2: Connect to your Server

If you are on Windows, open **PowerShell**. If you are on Mac/Linux, open **Terminal**. Type the following command (replace `YOUR_VPS_IP` with the actual IP address of your server):

```bash
ssh root@YOUR_VPS_IP
```
*If it asks "Are you sure you want to continue connecting?", type `yes` and press Enter. Then paste your password.*

## Step 3: Install Rust

Primus is built in Rust, so we need to install it to run the node. Paste this command into the server and press Enter:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
When it prompts you with options (`1) Proceed with installation (default)`), just press **Enter**.

After it finishes, run this command to refresh your shell so it recognizes Rust:
```bash
source $HOME/.cargo/env
```

## Step 4: Open the Firewall Port

Primus uses port `9000` (UDP) to communicate. We need to tell the server's firewall to allow traffic on this port. Run these commands one by one:

```bash
ufw allow 9000/udp
ufw allow ssh
ufw enable
```
*If it asks to proceed with `ufw enable`, press `y` and Enter.*

## Step 5: Download the Primus Code

Now we need to get the actual Primus messenger code onto your server. (Assuming you have it on GitHub, replace the URL. If not, just upload your files via SFTP). For this example, let's clone the repository:

```bash
# First, install git just in case
apt update && apt install -y git

# Download the code (Change URL to your actual repo if needed)
git clone https://github.com/LeechoShoop/messenger.git primus
cd primus
```

## Step 6: Start the Seed Node!

We have a simple script prepared just for Linux to run the node without any hassle. First, we need to make the script executable:

```bash
chmod +x linux-seed.sh
```

Now, run the script!

```bash
./linux-seed.sh
```

**🎉 Congratulations!**
Your node will now compile (this takes a few minutes the first time) and then start running.
You will see logs indicating it is listening on port `9000`. 
Your Node's keys and database are safely stored in the `primus-seed-data` folder. Even if you restart the server, your node will keep its identity!

---

### Keeping it running in the background (Optional but Recommended)
If you close your terminal window right now, the node will stop. To keep it running forever in the background, you can use a tool called `screen`:

1. Stop the current node by pressing `Ctrl + C`.
2. Start a new background session by typing: `screen -S primus`
3. Run the script again: `./linux-seed.sh`
4. Now, detach from the session by pressing **Ctrl + A**, then **D**.
5. You can safely close your terminal! The node will stay online forever.
*(To check on it later, log back into the server and type `screen -r primus`).*

---

## How to connect to your new Node?

Tell your friends to use your server's IP address when they launch their Primus client!

**On Windows:**
```powershell
$env:PRIMUS_SEEDS="YOUR_VPS_IP:9000"
cargo run --bin messenger-tui
```

**On Mac/Linux:**
```bash
PRIMUS_SEEDS="YOUR_VPS_IP:9000" cargo run --bin messenger-tui
```

Your server will now introduce everyone on the network to each other!
