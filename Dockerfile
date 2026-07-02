# HyperTraceX Docker Container
# Enterprise Digital Forensics Platform
# docker build -t tracex .
# docker run -it --privileged tracex

FROM kalilinux/kali-rolling:latest

LABEL maintainer="CR0WNNE0_fuxv>#SUDOIT"
LABEL description="HyperTraceX - Enterprise Digital Forensics Platform"
LABEL version="1.0.0"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    python3 \
    python3-pip \
    python3-dev \
    aircrack-ng \
    reaver \
    hcxtools \
    hashcat \
    tshark \
    tcpdump \
    testdisk \
    photorec \
    sqlite3 \
    tesseract-ocr \
    p7zip-full \
    unrar-free \
    git \
    nano \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/tracex

COPY requirements.txt .
RUN pip3 install --break-system-packages -r requirements.txt

COPY . .

RUN chmod +x tracex.py install.sh
RUN ln -sf /opt/tracex/tracex.py /usr/local/bin/tracex

VOLUME ["/cases", "/evidence", "/output"]

ENTRYPOINT ["python3", "tracex.py"]
CMD ["--help"]
