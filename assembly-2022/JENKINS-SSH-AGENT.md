# Run Jenkins builds on blackbox over SSH (assembly-4)

Goal: the Jenkins controller on assembly-4 connects to blackbox (Linux) over SSH,
copies its agent there, and runs builds on it.

- Login user on blackbox: `ubuntu` (not `jenkins`, which doesn't exist there).
- blackbox IP: `198.18.1.249` when this was set up. Check it again on the day.
- Time: about 5 minutes. Most of it is the Java install.

> **Check before you do this.** blackbox is the organizers' log box and is out
> of Red Team's scope. Make sure the rules allow running builds on it. The
> controller also stores an SSH login for blackbox, so anyone who takes over
> Jenkins can get onto blackbox with it. Use a login without sudo if you can.

## 1. Prepare blackbox (in a shell on blackbox)

Install Java. Without it the agent fails with `java: command not found`.

```bash
sudo apt-get update && sudo apt-get install -y openjdk-21-jre-headless
java -version
which java          # usually /usr/bin/java; you need this in step 2
```

- The agent needs Java 17 or newer. Best is the same major version as the
  controller. In Jenkins, go to **Manage Jenkins > System Information** and
  look at `java.version`.
- **Don't create the agent folder yourself**, and never with `sudo mkdir`.
  Jenkins creates it in step 3. A folder that root made is the classic cause
  of the "Permission denied" copy error.

## 2. Add the node (in the Jenkins web UI)

Go to **Manage Jenkins > Nodes > New Node**. Give it a name (for example
`blackbox`), pick **Permanent Agent**, then fill in:

| Field | Value |
|---|---|
| Remote root directory | `/home/ubuntu/jenkins` (must be a folder the login user can write to) |
| Labels | `blackbox` (jobs use this to pick the node) |
| Usage | Only build jobs with label expressions matching this node |
| Launch method | Launch agents via SSH |
| Host | blackbox's IP |
| Credentials | **Add**: "SSH Username with private key" or "Username with password", username `ubuntu` |
| Host Key Verification Strategy | Manually trusted key Verification Strategy (trusts the key on the first connect) |
| Advanced > JavaPath | `/usr/bin/java` (the `which java` output) |

Click **Save** at the very bottom. If you leave without saving, your changes
are lost and the next launch uses the old values.

## 3. Launch and check

Open the node and click **Launch agent** (or **Relaunch**), then **Log**.
A good log goes in this order:

```
[SSH] Authentication successful.
[SSH] Remote file system root /home/ubuntu/jenkins does not exist. Will try to create it...
[SSH] Copying latest remoting.jar...
[SSH] Copied 1,418,560 bytes.
[SSH] Starting agent process: cd "/home/ubuntu/jenkins" && java -jar remoting.jar ...
Agent successfully connected and online
```

## 4. Make a job run there

Open the job, then **Configure**. Under **General**, check **Restrict where
this project can be run** and enter the label `blackbox`. Save, then click
**Build Now**. The build's console output starts with
`Building remotely on blackbox`.

## Errors seen and fixes

| Log says | Cause | Fix |
|---|---|---|
| `Could not copy remoting.jar into '/home/jenkins'` ... `SSH_FX_PERMISSION_DENIED` | `ubuntu` can't write to `/home`. That folder is the default "Remote root directory", and it's the wrong one here. | Set Remote root directory to `/home/ubuntu/jenkins` and **Save**. |
| Same error with `/home/ubuntu/jenkins` | The folder already exists and belongs to root (someone made it with `sudo`). | `ls -ld /home/ubuntu/jenkins`. Then either `sudo chown -R ubuntu:ubuntu /home/ubuntu/jenkins` or delete it and let Jenkins create it. |
| Old path comes back in the log | Not saved, or you launched a different node with the same host. | Check the node's Configure page, and look under **Nodes** for a second entry with the same IP. |
| `java: command not found`, `Exit code=127` | Java isn't installed, or isn't on the PATH of the non-interactive SSH shell. | Step 1, then set **JavaPath** to `/usr/bin/java`. |
| `UnsupportedClassVersionError` | The agent's Java is older than the controller needs. | Install a newer JDK (17 or 21). |
| `apt-get` can't download anything | blackbox has no outbound internet. | Download the `.deb` on a machine that has internet, copy it over, run `sudo apt install ./file.deb`. Or unpack a JDK tarball and point **JavaPath** at its `bin/java`. |

## Roll back

Open the node and click **Disconnect**, then **Delete Agent**. On blackbox,
`rm -rf /home/ubuntu/jenkins` removes everything it left. Remove the stored
SSH login under **Manage Jenkins > Credentials** too, so it isn't left on the
controller.
