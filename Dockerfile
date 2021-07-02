FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE 1

COPY --from=zricethezav/gitleaks:latest /usr/bin/gitleaks /usr/bin/gitleaks

WORKDIR /check-gitleaks

COPY . /check-gitleaks/

RUN apt-get update && \
    apt-get install -y git

RUN pip install pybuilder && \
    pyb install_dependencies --no-venvs && \
    pyb install --no-venvs
