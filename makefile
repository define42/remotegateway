all:
	docker compose stop
	docker compose build
	docker compose up

rdp:
	xfreerdp /gt:https   /gateway-usage-method:detect   /v:workstation /gu:hackers /gp:dogood  /g:localhost:8443   /u:ubuntu   /p:ubuntu   /cert:ignore /gt:https  -sec-rdp

