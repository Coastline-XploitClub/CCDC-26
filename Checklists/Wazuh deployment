# Wazuh deployment

## Purpose
This procedure is to deploy Wazuh on a Debian/Ubuntu-based system using Docker Compose.

1. Install the Docker keyring
```bash
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
```
2. Add the docker repostiory to `apt`
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
