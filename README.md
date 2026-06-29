# CRYSTALL
dual-core proxy client.

Клиент построен на базе ядра sing-box, что позволяет использовать правила маршрутизации как для
xray, так и для sing-box в целом.
CRYSTALL поддерживает парсинг ссылок панелей 3x-ui, CELERITY, S-UI и остальных.
Пока что поддерживает только VLESS и Hysteria2.

# DUAL-CORE

Для запуска ядра Xray система использует прослойку в виде sing-box, который
является маршрутизатором трафика.

Весь траФик системы -> sing-box -> Xray

Sing-box в данном случае является ТОЛЬКО маршрутизатором, не выполняя никаких действий с пакетами.

# RULES

Правила были организованы на подобии Clash системы.
PROCESS-NAME, PROCESS-PATH, DOMAIN, DOTDOMAIN (тот же DOMAIN-SUFFIX), DOMAIN-SUFFIX, MATCH
Учтите, что правило MATCH не имеет value, и ставиться в конце. Иначе правила, стоящие после MATCH будут пропущены.
Правила применяются сверху вниз, верхнее правило побеждает.

Учтите, некоторые блоки кода написаны AI.

# Большое Спасибо:
sing-box - https://github.com/SagerNet/sing-box
xray - https://github.com/XTLS/Xray-core
Clash Verge Rev - https://github.com/clash-verge-rev/clash-verge-rev
V2rayN - https://github.com/2dust/v2rayN

Этот клиент написан под меня и мои потербности и потребности моих друзей. Но я буду рад вашим Pull Requests! Это мой первый проект, не судите строго :)
