# mpgitleaks
[![complexity](https://img.shields.io/badge/complexity-Simple:%205-brightgreen)](https://radon.readthedocs.io/en/latest/api.html#module-radon.complexity)
[![vulnerabilities](https://img.shields.io/badge/vulnerabilities-None-brightgreen)](https://pypi.org/project/bandit/)
[![python](https://img.shields.io/badge/python-3.9-teal)](https://www.python.org/downloads/)

A Python script that wraps the [gitleaks](https://github.com/zricethezav/gitleaks) tool to enable scanning of multiple repositories in parallel. 

This wrapping script was written for a few reasons:
* implement workaround for `gitleaks` intermittent failures when cloning very large repositories
* implement ability to scan multiple repostiories in parallel
* implement ability to scan all repositories for the authenticated user or a specified organization

Notes:
* ssh urls must be supplied when using `--file` option
* the script uses ssh to clone the repos thus you must have an ssh key configured on the GitHub instance
* the Docker container must run with your .ssh folder bind mounted
* the maximum number of background processes (workers) that will be started is `35`
* the script will start one worker per repository unless the total number of repos exceeds the maximum number of workers
* if total number of repos exceeds maximum workers, the repos will be added to a thread-safe queue and processed by the workers
* the repos will be cloned to the `./scans/clones` folder in the working directory
* the reports will be written to the `./scans/reports/` folder in the working directory


## Usage
```bash
usage: mpgitleaks [-h] [--file FILENAME] [--user] [--org ORG] [--exclude EXCLUDE] [--include INCLUDE] [--progress]

A Python script that wraps the gitleaks tool to enable scanning of multiple repositories in parallel

optional arguments:
  -h, --help         show this help message and exit
  --file FILENAME    file containing repositories to process - default file is repos.txt
  --user             process repos for the authenticated user
  --org ORG          process repos for the specified GitHub organization
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

Get repos from a file named `repos.txt` but exclude the specified repos and display progress bar:
```bash
mpgitleaks --file 'repos.txt' --exclude 'soda480/mplogp' --progress
```
![example](https://raw.githubusercontent.com/soda480/mpgitleaks/master/docs/images/example1.gif)

Get all repos for the authenticated user but exclude the specified repos:
```bash
mpgitleaks --user --exclude 'intel|edgexfoundry|soda480/openhack'
```

Get alls repos for the specified organization and include only the specified repos:
```bash
mpgitleaks --org 'myorg' --include '.*-go'
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