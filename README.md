## check-gitleaks
A Python script that wraps the gitleaks tool to enable scanning of multiple repositories in parallel

### `check-gitleaks` Usage
usage: check-gitleaks [-h] [--file FILENAME]

A Python script that wraps the gitleaks tool to enable scanning of multiple repositories in parallel

optional arguments:
  -h, --help       show this help message and exit
  --file FILENAME  file containing repositories to scan

Clone the repository and ensure the lastest verison of Docker is installed on your system.

Build the Docker image:
```bash
docker image build \
--build-arg http_proxy \
--build-arg https_proxy \
-t \
check-gitleaks:latest .
```

Execute the Docker container:
```bash
docker container run \
--rm \
-it \
-e http_proxy \
-e https_proxy \
-v $PWD:/check-gitleaks \
-v $PWD/output:/output \
-v $HOME/.ssh:/root/.ssh \
check-gitleaks:latest \
/bin/bash
```

Set required environment variables:
```bash
export GH_BASE_URL=api.github.com
export GH_TOKEN_PSW=--your-token--
```

Create a file `repos.txt` include ssh address url of all repos to scan.

Execute the script:
```bash
check-gitleaks --file repos.txt
```

