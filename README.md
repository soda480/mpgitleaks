# mpgitleaks
A Python script that wraps the [gitleaks](https://github.com/zricethezav/gitleaks) tool to enable scanning of multiple repositories in parallel

## Usage
```bash
usage: mpgitleaks [-h] [--file FILENAME] [--exclude EXCLUDE] [--include INCLUDE] [--progress]

A Python script that wraps the gitleaks tool to enable scanning of multiple repositories in parallel

optional arguments:
  -h, --help         show this help message and exit
  --file FILENAME    file containing repositories to scan
  --exclude EXCLUDE  a regex to match name of repos to exclude from processing
  --include INCLUDE  a regex to match name of repos to include in processing
  --progress         display progress bar for each process
```

## Execution

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

### Examples
Examples showing various command options.

Read repos from `my-repos.txt` file include repos that begin with `pybuilder` or `mp` but exclude `mpcurses` repo

```bash
mpgitleaks --file 'my-repos.txt' --include 'soda480/pybuilder-|soda480/mp' --exclude 'soda480/mpcurses' --progress
```

Get repos for authenticated user and process only those that start with `soda480/`
```bash
mpgitleaks --user --include 'soda480/'
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