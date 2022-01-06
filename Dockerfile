FROM python:3.8-alpine

EXPOSE 5000/tcp

WORKDIR /tonybot

COPY requirements.txt .

COPY tony_quotes.txt .

RUN pip install -r requirements.txt

COPY tonybot.py .

COPY utils.py .

#CMD ["python", "tonybot.py"]

ENV FLASK_APP="tonybot.py"

#CMD ["export", "FLASK_APP=FLASK_APP.py"]

CMD ["flask", "run", "--host", "0.0.0.0"]
