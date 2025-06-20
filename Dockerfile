FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    git \
    libssl-dev \
    libboost-all-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Télécharger et installer CMake officiel
RUN wget https://github.com/Kitware/CMake/releases/download/v3.30.5/cmake-3.30.5-linux-x86_64.sh  && \
    chmod +x cmake-3.30.5-linux-x86_64.sh  && \
    ./cmake-3.30.5-linux-x86_64.sh  --skip-license --prefix=/usr/local && \
    rm cmake-3.30.5-linux-x86_64.sh 

WORKDIR /app

COPY . .

RUN rm CMakeLists.txt && mv CMakeLists.docker.txt CMakeLists.txt

RUN mkdir build && cd build && cmake .. && cmake --build . --config Release

CMD ["sleep", "infinity"]
