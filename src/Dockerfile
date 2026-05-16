ARG PYVERSION=3.14.2
FROM docker.io/library/python:${PYVERSION}-slim

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY configauditreport.py ./
COPY vulnerabilityreport.py ./
COPY main.py ./
COPY ticket.py ./
COPY watcher.py ./

CMD [ "python", "./main.py" ]

