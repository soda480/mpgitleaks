FROM python:3.9-slim AS build
ENV PYTHONDONTWRITEBYTECODE 1
COPY --from=zricethezav/gitleaks:latest /usr/bin/gitleaks /usr/bin/gitleaks
WORKDIR /mpgitleaks
COPY . /mpgitleaks/
RUN apt-get update && \
    apt-get install -y git
RUN pip install pybuilder && \
    pyb install_dependencies --no-venvs && \
    pyb install --no-venvs


FROM python:3.9-alpine
ENV PYTHONDONTWRITEBYTECODE 1
COPY --from=zricethezav/gitleaks:latest /usr/bin/gitleaks /usr/bin/gitleaks
WORKDIR /opt/mpgitleaks
COPY --from=build /mpgitleaks/target/dist/mpgitleaks-*/dist/mpgitleaks-*.tar.gz /opt/mpgitleaks
RUN apk add --update git openssh
RUN pip install mpgitleaks-*.tar.gz
ENTRYPOINT ["mpgitleaks"]