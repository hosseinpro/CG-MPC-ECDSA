FROM --platform=linux/amd64 rust

# RUN rustup component add rustfmt clippy
RUN apt-get update && apt-get install iputils-ping -y

