# Docker

## Docker Hub

Официальный образ контейнера доступен по адресу https://hub.docker.com/r/sergvuntyped/byedpi.

Образы тегируются по полному номеру версии (`major.minor.patch`) и `major.minor`. Последний стабильный релиз имеет тег `latest`.

## Сборка

Чтобы собрать образ контейнера из исходного кода, выполните:

docker build . --tag my/byedpi