# Jenkins SSH agent on blackbox

Login `ubuntu`, IP `198.18.1.249` (check it on the day). blackbox is out of
scope, so make sure the rules allow building on it.

## 1. On blackbox

```bash
sudo apt-get update && sudo apt-get install -y openjdk-21-jre-headless
java -version
which java          # usually /usr/bin/java; you need this in step 2
```

Don't make the agent folder yourself (especially not with `sudo`). Jenkins
makes it.

## 2. In Jenkins

New Node (Permanent Agent). Set:

- Remote root directory: `/home/ubuntu/jenkins`
- Labels: `blackbox`
- Launch via SSH: host = blackbox IP, credentials = `ubuntu`
- JavaPath (Advanced): `/usr/bin/java`

Save, Launch. The log should end with `Agent successfully connected and online`.

To run a job there: job Configure > **Restrict where this project can be run** > `blackbox`.

## If it fails

- **`Could not copy remoting.jar` ... `Permission denied`**: `ubuntu` can't
  write to the root directory. Use `/home/ubuntu/jenkins`. If it still fails,
  the folder already exists and belongs to root:
  `sudo chown -R ubuntu:ubuntu /home/ubuntu/jenkins`.
- **Log shows the old path**: you didn't click Save.
- **`java: command not found`**: do step 1, and set JavaPath.
