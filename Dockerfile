FROM python:3.9-slim AS build
LABEL maintainer="Emilio Reyes soda480@gmail.com"
ENV PYTHONDONTWRITEBYTECODE 1
COPY --from=zricethezav/gitleaks:v8.5.1 /usr/bin/gitleaks /usr/bin/gitleaks
WORKDIR /code
COPY . /code/
RUN apt-get update && \
    apt-get install -y git
RUN pip install pybuilder && \
    pyb install


FROM python:3.9-alpine
ENV PYTHONDONTWRITEBYTECODE 1
COPY --from=zricethezav/gitleaks:v8.5.1 /usr/bin/gitleaks /usr/bin/gitleaks
WORKDIR /opt/mpgitleaks
COPY --from=build /code/target/dist/mpgitleaks-*/dist/mpgitleaks-*.tar.gz /opt/mpgitleaks
RUN apk add --update git
RUN pip install mpgitleaks-*.tar.gz
ENTRYPOINT ["mpgitleaks"]