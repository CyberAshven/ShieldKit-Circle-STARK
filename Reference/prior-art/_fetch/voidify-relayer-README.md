# Voidify Relayer Docker Deployment

[English](README.md) | [中文](docs/README.zh-CN.md) | [Русский](docs/README.ru.md) | [日本語](docs/README.ja.md)

## Install Docker on Ubuntu

```sh
sudo apt update
sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources > /dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker run hello-world
```

## Quick Start

1. Copy the example environment file:

   ```sh
   cp .env.example .env
   ```

2. Edit `.env` and set `DOMAIN`, `VOIDIFY_PROGRAM_ID`, and either a base58 private key:

   ```dotenv
   DOMAIN=relayer.example.com
   VOIDIFY_PROGRAM_ID=your_voidify_program_id
   VOIDIFY_KEYPAIR_BASE58=your_base58_private_key
   ```

   Or use a keypair JSON file instead:

   ```dotenv
   DOMAIN=relayer.example.com
   VOIDIFY_PROGRAM_ID=your_voidify_program_id
   RELAYER_KEYPAIR_FILE=/absolute/path/to/relayer-keypair.json
   ```

3. Keep `RELAYER_PORT` aligned with the port exposed by the relayer service.

4. Make sure `DOMAIN` resolves to this server and that ports `80` and `443` are reachable.

5. Build the Docker images:

   ```sh
   docker compose build
   ```

6. Start the deployment:

   ```sh
   docker compose up -d
   ```

7. Stop the deployment:

   ```sh
   docker compose down
   ```

8. View logs (press <kbd>Ctrl</kbd>+<kbd>C</kbd> to quit):

   ```sh
   docker compose logs -f
   ```

## Update

Before updating, keep your `.env` file and keypair file. Do not delete `caddy-data`, because it contains Caddy's certificate state.

1. Stop the current deployment:

   ```sh
   docker compose down
   ```

2. Pull the latest code, or replace the existing project files with the files from the latest release.

3. Delete the old generated relayer config so the new version can create a fresh one:

   ```sh
   rm -f relayer-data/relayer.json
   ```

4. Compare `.env` with `.env.example` and update it if any variables have changed.

5. Rebuild and start the deployment:

   ```sh
   docker compose build
   docker compose up -d
   ```

6. Check that the services started successfully:

   ```sh
   docker compose logs -f
   ```

## Details

The container writes its generated relayer config to `./relayer-data/relayer.json` on first start, then updates it from `.env` on each start.

`RELAYER_KEYPAIR_FILE` is the path to a keypair JSON file on the host. Docker Compose mounts it read-only into the relayer container. If both `VOIDIFY_KEYPAIR_BASE58` and `RELAYER_KEYPAIR_FILE` are set, `VOIDIFY_KEYPAIR_BASE58` takes precedence and the entrypoint ignores the mounted keypair file.

Caddy terminates HTTPS and renews certificates automatically. Its certificate state is stored in `./caddy-data`, while runtime configuration and cache files are stored in `./caddy-config`.
