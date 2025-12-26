all:
	docker compose stop
	docker compose build
	docker compose up

rdp:
	xfreerdp /gt:https   /gateway-usage-method:detect   /v:workstation /gu:ubuntu /gp:ubuntu  /g:localhost:8443   /u:ubuntu   /p:ubuntu   /cert:ignore /gt:https  -sec-rdp

