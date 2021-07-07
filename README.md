
# mpgitleaks
[![build](https://github.com/soda480/mpgitleaks/actions/workflows/main.yml/badge.svg)](https://github.com/soda480/mpgitleaks/actions/workflows/main.yml)
[![complexity](https://img.shields.io/badge/complexity-Simple:%204-brightgreen)](https://radon.readthedocs.io/en/latest/api.html#module-radon.complexity)
[![vulnerabilities](https://img.shields.io/badge/vulnerabilities-None-brightgreen)](https://pypi.org/project/bandit/)
[![python](https://img.shields.io/badge/python-3.9-teal)](https://www.python.org/downloads/)

A Python script that wraps the [gitleaks](https://github.com/zricethezav/gitleaks) tool to enable scanning of multiple repositories in parallel. 

The motivation behind writing this script was:
* implement workaround for `gitleaks` intermittent failures when cloning very large repositories
* implement ability to scan multiple repostiories in parallel
* implement ability to scan repositories for a user, a specified organization or read from a file

**Notes**:
* the script uses https to clone the repos
  * you must set the `GH_TOKEN_PSW` to a 'personal access token' that has access to the repos being scanned
  * if using `--file` then https clone urls must be supplied in the file
* the maximum number of background processes (workers) that will be started is `35`
  * if the number of repos to process is less than the maximum number of workers
    * the script will start one worker per repository
  * if the number of repos to process is greater than the maximum number of workers
    * the repos will be added to a thread-safe queue and processed by all the workers
* the Docker container must run with a bind mount to the working directory in order to access logs/reports
  * the repos will be cloned to the `./scans/clones` folder in the working directory
  * the reports will be written to the `./scans/reports/` folder in the working directory


## Usage
```bash
usage: mpgitleaks [-h] [--file FILENAME] [--user] [--org ORG] [--exclude EXCLUDE] [--include INCLUDE] [--noprogress] [--log] [--branches]

A Python script that wraps the gitleaks tool to enable scanning of multiple repositories in parallel

optional arguments:
  -h, --help         show this help message and exit
  --file FILENAME    process repos contained in the specified file
  --user             process repos for the authenticated user
  --org ORG          process repos for the specified organization
  --exclude EXCLUDE  a regex to match name of repos to exclude from scanning
  --include INCLUDE  a regex to match name of repos to include in scanning
  --noprogress       do not display progress bar for each process - display log messages instead
  --log              log messages to a log file
  --branches         set process affinity at repo branch level
```

## Execution

Set the required environment variables:
```bash
export GH_BASE_URL=api.github.com
export GH_TOKEN_PSW=--your-token--
```

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
soda480/mpgitleaks:latest \
[MPGITLEAKS OPTIONS]
```

**Note**: the `http[s]_proxy` environment variables are only required if executing behind a proxy server

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

Clone the repository and ensure the latest version of Docker is installed on your development server.

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