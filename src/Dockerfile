FROM prive.gounix.nl/docker.io/library/python:3.14.2-slim

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY configauditreport.py ./
COPY vulnerabilityreport.py ./
COPY main.py ./
COPY ticket.py ./
COPY watcher.py ./

CMD [ "python", "./main.py" ]

