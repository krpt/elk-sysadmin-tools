# ELK Sysadmin Tools

A curated collection of system administration scripts and operational automation tools for managing and maintaining ELK Stack environments (Elasticsearch, Logstash, Kibana).

## 📦 Included Tools

### 🔧 `elasticsearch/rolling_restart.py`

Safely restart a single Elasticsearch node without triggering unnecessary shard reallocation or IO overhead.

#### Features

- Disables shard reallocation pre-restart (`primaries` only)
- Flushes transaction logs for faster recovery
- Stops/starts the node with `systemctl`
- Waits for the node to rejoin and cluster to reach `green` state
- Re-enables full shard allocation
- Resets `delayed_timeout` to default
- Interactive with pause/confirmation at each step
- Logs all requests and responses to file
- `--export-commands`: generates a shell script with equivalent `curl`/`systemctl` commands
- `--resume-post-restart`: resume only the final recovery steps after restart

#### Usage

```bash
python3 rolling_restart.py --password 'your-elastic-password'
