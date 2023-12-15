FROM ubuntu:18.04


LABEL maintainer="dongchaopeng@iie.ac.cn"

SHELL ["/bin/bash", "-c"]


RUN apt-get update && \
    apt-get install -y \
    wget \
    bzip2 \
    git

RUN mkdir /root/miniconda3 && \
    wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O /root/miniconda3/miniconda.sh && \
    bash /root/miniconda3/miniconda.sh -b -u -p /root/miniconda3 && \
    rm -rf /root/miniconda3/miniconda.sh && \
    /root/miniconda3/bin/conda init bash


RUN mkdir -p /root/LibvDiff

COPY . /root/LibvDiff
WORKDIR /root/LibvDiff

RUN /root/miniconda3/bin/conda create -y --name libvdiff python=3.8
RUN /root/miniconda3/bin/conda install -y -n libvdiff pytorch==1.12.1 torchvision==0.13.1 torchaudio==0.12.1 -c pytorch
RUN /root/miniconda3/envs/libvdiff/bin/python -m pip install -r requirements.txt




