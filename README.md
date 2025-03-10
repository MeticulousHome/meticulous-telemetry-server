# Meticulous Telemetry Upload server

A minimal rust server to accept a compressed debug shot file and potentially additional metadata. 
Data retention is implemented via an external cron job, rate limiting in nginx.

### Run
Execution is done via docker / compose:
`docker compose up -d --build`

### Request format
The server accepts request of this format:
```
export MACHINE_NAME=meticulousDevMimoja
export FILE=./2025-01-29/17\:31\:53.shot.json.zst
curl https://analytics.meticulousespresso.com/upload/${MACHINE_NAME} -F file=@${FILE} -F 'json={"config": {}};type=application/json'
```
Where the json::config field can contain arbitrary data as long as it is valid json
