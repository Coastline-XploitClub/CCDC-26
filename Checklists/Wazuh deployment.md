# Wazuh deployment

## Purpose
This procedure is to deploy Wazuh on a Debian/Ubuntu-based system using Docker Compose.


## Installation 

### Install Docker
1. Install the Docker keyring
> Replace `ubuntu` with `debian` if installing on debian
```bash
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
```
2. Add the docker repostiory to `apt`
> Replace `ubuntu` with `debian` if installing on debian
```bash
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")  # May have to subsitute this for the actual command output ex. `trixie`
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF
```
3. Update and install Docker
```bash
sudo apt update && sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
4. Add user to docker group
```
sudo usermod -aG docker <user>
```

### Install Wazuh
1. Set vm memory mappingg
```bash
sysctl -w vm.max_map_count=262144
```
2. Clone the git repository
```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.1
cd wazuh-docker/single-node
```
3. Generate the certs
```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```
4. Deploy the wazuh containers
```bash
docker compose up -d
```
5. Log in with default credentials to the HTTPS port (443) and change them `admin:SecretPassword`. It may take a couple mins to come up

### Deploy agents
1. In Wazuh, go to **Agent Management > Summary** and create a new deployment
2. Use `deb amd64` for debian/ubuntu machines and `rpm amd64` for rpm-based distros for linux, otherwise choose windows installer
3. Use **IP ADDRESS** of wazuh server for `Server address`
4. Leave all else at default
5. Copy and run commands provided in wizard
6. Go back to agent summary page, you should see agents in a couple of mins.

### Agent configuration
1. Edit the wazuh configuration (`/var/ossec/etc/ossec.conf` on linux, and `C:\Program Files (x86)\ossec-agent\ossec.conf` on Windows)
2. Ensure `<disabled>` is set to `no`
3. Change the `<frequency>` value to a short time (starting point is 120 seconds and increase/decrease as necessary)
4. Change the `<directories>` to add the `realtime="yes"` attribute (ex. `<directories realtime="yes">`
5. Add additional `<directories>` lines or modify existing as needed (ex. to include web server config files)
6. Restart wazuh service (linux: `systemctl restart wazuh-agent`, windows: `Restart-Service -Name wazuh`)
