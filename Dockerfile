FROM ubuntu:20.04

RUN adduser --disabled-password --gecos '' user

RUN apt update \
  && apt install -y --no-install-recommends \
  build-essential \
  iproute2 \
  iputils-ping \
  netcat-openbsd \
  git \
  sudo \
  && apt clean -y \
  && rm -rf /var/lib/apt/lists

RUN echo 'user ALL=(root) NOPASSWD:ALL' > /etc/sudoers.d/user
USER user
WORKDIR /microps

COPY --chown=user:user docker-entrypoint.sh .
RUN sudo chmod u+x ./docker-entrypoint.sh
