# mpgitleaks
A Python script that wraps the [gitleaks](https://github.com/zricethezav/gitleaks) tool to enable scanning of multiple repositories in parallel

## Usage
```bash
usage: mpgitleaks [-h] [--file FILENAME]

A Python script that wraps the gitleaks tool to enable scanning of multiple repositories in parallel

optional arguments:
  -h, --help       show this help message and exit
  --file FILENAME  file containing repositories to scan
```

## Example

Clone the repository and ensure the lastest verison of Docker is installed on your system.

Build the Docker image:
```bash
docker image build \
--build-arg http_proxy \
--build-arg https_proxy \
-t \
mpgitleaks:latest .
```

Set required environment variables:
```bash
export GH_BASE_URL=api.github.com
export GH_TOKEN_PSW=--your-token--
```

Create a file `repos.txt` in $PWD that contains the ssh address url of all repos to scan.

Execute the Docker container:
```bash
docker container run \
--rm \
-it \
-e http_proxy \
-e https_proxy \
-e GH_BASE_URL \
-e GH_TOKEN_PSW \
-v $PWD:/opt/mpgitleaks \
-v $HOME/.ssh:/root/.ssh \
mpgitleaks:latest \
[OPTIONS]
```

## Development

Build the Docker image:
```bash
docker image build \
--target build \
--build-arg http_proxy \
--build-arg https_proxy \
-t \
mpgitleaks:latest .
```

Run the Docker container:
```bash
docker container run \
--rm \
-it \
-e http_proxy \
-e https_proxy \
-v $PWD:/mpgitleaks \
mpgitleaks:latest \
/bin/bash
```

Build application:
```bash
pyb -X --no-venvs
```