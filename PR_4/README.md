# Практическая работа 4. Исследование метаданных DNS трафика.
TrystNB@ya.ru

## Цель работы

1.  Зекрепить практические навыки использования языка программирования R
    для обработки данных
2.  Закрепить знания основных функций обработки данных экосистемы языка
    R
3.  Закрепить навыки исследования метаданных DNS трафика

## Исходные данные

1.  Оепрационная система Windows 11
2.  RStudio
3.  Интерпретатор языка R

## Задание

Используя программный пакет dplyr, освоить анализ DNS логов с помощью
языка программирования R.

## Впоросы

1.  Импортируйте данные DNS. Определите формат данных. Данные были
    собраны с помощью сетевого анализатора Zeek.
2.  Добавьте пропущенные данные о структуре данных (назначении
    столбцов).
3.  Преобразуйте данные в столбцах в нужный формат.
4.  Просмотрите общую структуру данных с помощью функции glimpse().
5.  Сколько участников информационного обмена в сети Доброй Организации?
6.  Какое соотношение участников обмена внутри сети и участников
    обращений к внешним ресурсам?
7.  Найдите топ-10 участников сети, проявляющих наибольшую сетевую
    активность.
8.  Найдите топ-10 доменов, к которым обращаются пользователи сети и
    соответственное количество обращений.
9.  Определите базовые статистические характеристики интервала времени
    между последовательными обращениями к топ-10 доменам.
10. Часто вредоносное программное обеспечение использует DNS канал в
    качестве канала управления, периодически отправляя запросы на
    подконтрольный злоумышленникам DNS сервер. По периодическим запросам
    на один и тот же домен можно выявить скрытый DNS канал. Есть ли
    такие IP адреса в исследуемом датасете?
11. Определите местоположение (страну, город) и организацию-провайдера
    для топ-10 доменов.

## Выполнение задания

### 

### 1. Импортируйте данные DNS. Определите формат данных. Данные были собраны с помощью сетевого анализатора Zeek.

    library(dplyr)
    library(readr)
    library(tidyr)
    library(lubridate)

    ...

    > url <- "https://storage.yandexcloud.net/dataset.ctfsec/dns.zip"
    > download.file(url, "dns.zip")
    пробую URL 'https://storage.yandexcloud.net/dataset.ctfsec/dns.zip'
    Content type 'application/zip' length 6407934 bytes (6.1 MB)
    downloaded 6.1 MB

    > unzip("dns.zip")
    > dns_data <- readr::read_tsv("dns.log", comment = "#", col_names = FALSE)
    > head(dns_data, 10)
    # A tibble: 10 × 23
                X1 X2                 X3           X4 X5       X6 X7       X8 X9    X10   X11   X12   X13   X14   X15   X16   X17   X18   X19     X20 X21   X22   X23  
             <dbl> <chr>              <chr>     <dbl> <chr> <dbl> <chr> <dbl> <chr> <chr> <chr> <chr> <chr> <chr> <chr> <lgl> <lgl> <lgl> <lgl> <dbl> <chr> <chr> <lgl>
     1 1331901006. CWGtK431H9XuaTN4fi 192.168.… 45658 192.…   137 udp   33008 "*\\… 1     C_IN… 33    SRV   0     NOER… FALSE FALSE FALSE FALSE     1 -     -     FALSE
     2 1331901015. C36a282Jljz7BsbGH  192.168.…   137 192.…   137 udp   57402 "HPE… 1     C_IN… 32    NB    -     -     FALSE FALSE TRUE  FALSE     1 -     -     FALSE
     3 1331901016. C36a282Jljz7BsbGH  192.168.…   137 192.…   137 udp   57402 "HPE… 1     C_IN… 32    NB    -     -     FALSE FALSE TRUE  FALSE     1 -     -     FALSE
     4 1331901017. C36a282Jljz7BsbGH  192.168.…   137 192.…   137 udp   57402 "HPE… 1     C_IN… 32    NB    -     -     FALSE FALSE TRUE  FALSE     1 -     -     FALSE
     5 1331901006. C36a282Jljz7BsbGH  192.168.…   137 192.…   137 udp   57398 "WPA… 1     C_IN… 32    NB    -     -     FALSE FALSE TRUE  FALSE     1 -     -     FALSE
     6 1331901007. C36a282Jljz7BsbGH  192.168.…   137 192.…   137 udp   57398 "WPA… 1     C_IN… 32    NB    -     -     FALSE FALSE TRUE  FALSE     1 -     -     FALSE
     7 1331901007. C36a282Jljz7BsbGH  192.168.…   137 192.…   137 udp   57398 "WPA… 1     C_IN… 32    NB    -     -     FALSE FALSE TRUE  FALSE     1 -     -     FALSE
     8 1331901006. ClEZCt3GLkJdtGGmAa 192.168.…   137 192.…   137 udp   62187 "EWR… 1     C_IN… 32    NB    -     -     FALSE FALSE TRUE  FALSE     1 -     -     FALSE
     9 1331901007. ClEZCt3GLkJdtGGmAa 192.168.…   137 192.…   137 udp   62187 "EWR… 1     C_IN… 32    NB    -     -     FALSE FALSE TRUE  FALSE     1 -     -     FALSE
    10 1331901008. ClEZCt3GLkJdtGGmAa 192.168.…   137 192.…   137 udp   62187 "EWR… 1     C_IN… 32    NB    -     -     FALSE FALSE TRUE  FALSE     1 -     -     FALSE

### 2. Добавьте пропущенные данные о структуре данных (назначении столбцов).

    > colnames(dns_data) <- c(
    +     "ts",           # Временная метка (timestamp)
    +     "uid",          # Уникальный идентификатор соединения
    +     "id.orig_h",    # IP-адрес источника
    +     "id.orig_p",    # Порт источника
    +     "id.resp_h",    # IP-адрес получателя
    +     "id.resp_p",    # Порт получателя
    +     "proto",        # Протокол транспорта (udp/tcp)
    +     "trans_id",     # Идентификатор транзакции DNS
    +     "query",        # Доменное имя запроса
    +     "qclass",       # Класс запроса
    +     "qclass_name",  # Имя класса запроса
    +     "qtype",        # Тип запроса
    +     "qtype_name",   # Имя типа запроса
    +     "rcode",        # Код ответа
    +     "rcode_name",   # Имя кода ответа
    +     "AA",           # Authoritative Answer (авторитетный ответ)
    +     "TC",           # Truncated (усеченный)
    +     "RD",           # Recursion Desired (рекурсия запрошена)
    +     "RA",           # Recursion Available (рекурсия доступна)
    +     "Z",            # Зарезервировано
    +     "answers",      # Ответы от сервера
    +     "TTLs",         # Time-to-Live значений
    +     "rejected"      # Флаг отклонения запроса
    + )
    > glimpse(dns_data)
    Rows: 427,935
    Columns: 23
    $ ts          <dbl> 1331901006, 1331901015, 1331901016, 1331901017, 1331901006, 1331901007, 1331901007, 1331901006, 1331901007, 1331901008, 1331901007, 133190100…
    $ uid         <chr> "CWGtK431H9XuaTN4fi", "C36a282Jljz7BsbGH", "C36a282Jljz7BsbGH", "C36a282Jljz7BsbGH", "C36a282Jljz7BsbGH", "C36a282Jljz7BsbGH", "C36a282Jljz7B…
    $ id.orig_h   <chr> "192.168.202.100", "192.168.202.76", "192.168.202.76", "192.168.202.76", "192.168.202.76", "192.168.202.76", "192.168.202.76", "192.168.202.8…
    $ id.orig_p   <dbl> 45658, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 45658, 45659, 45658, 137, 137, 137, 60821, 60821, 60821, 60821, 61184, 611…
    $ id.resp_h   <chr> "192.168.27.203", "192.168.202.255", "192.168.202.255", "192.168.202.255", "192.168.202.255", "192.168.202.255", "192.168.202.255", "192.168.…
    $ id.resp_p   <dbl> 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 5353, 5353, 137, 137, 137, 137, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, …
    $ proto       <chr> "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "…
    $ trans_id    <dbl> 33008, 57402, 57402, 57402, 57398, 57398, 57398, 62187, 62187, 62187, 62190, 62190, 62190, 0, 0, 33008, 34107, 32821, 32818, 3550, 3550, 3559…
    $ query       <chr> "*\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00", "HPE8AA67", "HPE8AA67", "HPE8AA67", "WPAD", "WPAD", "WPAD", "EWREP…
    $ qclass      <chr> "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "…
    $ qclass_name <chr> "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "…
    $ qtype       <chr> "33", "32", "32", "32", "32", "32", "32", "32", "32", "32", "33", "33", "33", "12", "12", "33", "32", "32", "32", "28", "28", "28", "28", "1"…
    $ qtype_name  <chr> "SRV", "NB", "NB", "NB", "NB", "NB", "NB", "NB", "NB", "NB", "SRV", "SRV", "SRV", "PTR", "PTR", "SRV", "NB", "NB", "NB", "AAAA", "AAAA", "AAA…
    $ rcode       <chr> "0", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "0", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "…
    $ rcode_name  <chr> "NOERROR", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "NOERROR", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-",…
    $ AA          <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, F…
    $ TC          <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, F…
    $ RD          <lgl> FALSE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TR…
    $ RA          <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, F…
    $ Z           <dbl> 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, …
    $ answers     <chr> "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "…
    $ TTLs        <chr> "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "…
    $ rejected    <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, F…

### 3. Преобразуйте данные в столбцах в нужный формат.

    > dns_data_clean <- dns_data %>%
    +     mutate(
    +         ts = as.POSIXct(ts, origin = "1970-01-01"),
    +         id.orig_p = as.numeric(id.orig_p),
    +         id.resp_p = as.numeric(id.resp_p),
    +         trans_id = as.numeric(trans_id),
    +         qclass = as.numeric(qclass),
    +         qtype = as.numeric(qtype),
    +         rcode = as.numeric(rcode)
    +     ) %>%
    +     as_tibble()
    > head(dns_data_clean, 10)
    # A tibble: 10 × 23
       ts                  uid      id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id query qclass qclass_name qtype qtype_name rcode rcode_name AA    TC    RD   
       <dttm>              <chr>    <chr>         <dbl> <chr>         <dbl> <chr>    <dbl> <chr>  <dbl> <chr>       <dbl> <chr>      <dbl> <chr>      <lgl> <lgl> <lgl>
     1 2012-03-16 16:30:05 CWGtK43… 192.168.…     45658 192.168.…       137 udp      33008 "*\\…      1 C_INTERNET     33 SRV            0 NOERROR    FALSE FALSE FALSE
     2 2012-03-16 16:30:15 C36a282… 192.168.…       137 192.168.…       137 udp      57402 "HPE…      1 C_INTERNET     32 NB            NA -          FALSE FALSE TRUE 
     3 2012-03-16 16:30:15 C36a282… 192.168.…       137 192.168.…       137 udp      57402 "HPE…      1 C_INTERNET     32 NB            NA -          FALSE FALSE TRUE 
     4 2012-03-16 16:30:16 C36a282… 192.168.…       137 192.168.…       137 udp      57402 "HPE…      1 C_INTERNET     32 NB            NA -          FALSE FALSE TRUE 
     5 2012-03-16 16:30:05 C36a282… 192.168.…       137 192.168.…       137 udp      57398 "WPA…      1 C_INTERNET     32 NB            NA -          FALSE FALSE TRUE 
     6 2012-03-16 16:30:06 C36a282… 192.168.…       137 192.168.…       137 udp      57398 "WPA…      1 C_INTERNET     32 NB            NA -          FALSE FALSE TRUE 
     7 2012-03-16 16:30:07 C36a282… 192.168.…       137 192.168.…       137 udp      57398 "WPA…      1 C_INTERNET     32 NB            NA -          FALSE FALSE TRUE 
     8 2012-03-16 16:30:06 ClEZCt3… 192.168.…       137 192.168.…       137 udp      62187 "EWR…      1 C_INTERNET     32 NB            NA -          FALSE FALSE TRUE 
     9 2012-03-16 16:30:07 ClEZCt3… 192.168.…       137 192.168.…       137 udp      62187 "EWR…      1 C_INTERNET     32 NB            NA -          FALSE FALSE TRUE 
    10 2012-03-16 16:30:07 ClEZCt3… 192.168.…       137 192.168.…       137 udp      62187 "EWR…      1 C_INTERNET     32 NB            NA -          FALSE FALSE TRUE 
    # ℹ 5 more variables: RA <lgl>, Z <dbl>, answers <chr>, TTLs <chr>, rejected <lgl>

### 4. Просмотрите общую структуру данных с помощью функции glimpse().

    > glimpse(dns_data_clean)
    Rows: 427,935
    Columns: 23
    $ ts          <dttm> 2012-03-16 16:30:05, 2012-03-16 16:30:15, 2012-03-16 16:30:15, 2012-03-16 16:30:16, 2012-03-16 16:30:05, 2012-03-16 16:30:06, 2012-03-16 16:…
    $ uid         <chr> "CWGtK431H9XuaTN4fi", "C36a282Jljz7BsbGH", "C36a282Jljz7BsbGH", "C36a282Jljz7BsbGH", "C36a282Jljz7BsbGH", "C36a282Jljz7BsbGH", "C36a282Jljz7B…
    $ id.orig_h   <chr> "192.168.202.100", "192.168.202.76", "192.168.202.76", "192.168.202.76", "192.168.202.76", "192.168.202.76", "192.168.202.76", "192.168.202.8…
    $ id.orig_p   <dbl> 45658, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 45658, 45659, 45658, 137, 137, 137, 60821, 60821, 60821, 60821, 61184, 611…
    $ id.resp_h   <chr> "192.168.27.203", "192.168.202.255", "192.168.202.255", "192.168.202.255", "192.168.202.255", "192.168.202.255", "192.168.202.255", "192.168.…
    $ id.resp_p   <dbl> 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 5353, 5353, 137, 137, 137, 137, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, …
    $ proto       <chr> "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "udp", "…
    $ trans_id    <dbl> 33008, 57402, 57402, 57402, 57398, 57398, 57398, 62187, 62187, 62187, 62190, 62190, 62190, 0, 0, 33008, 34107, 32821, 32818, 3550, 3550, 3559…
    $ query       <chr> "*\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00", "HPE8AA67", "HPE8AA67", "HPE8AA67", "WPAD", "WPAD", "WPAD", "EWREP…
    $ qclass      <dbl> 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, NA, NA, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1…
    $ qclass_name <chr> "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "C_INTERNET", "…
    $ qtype       <dbl> 33, 32, 32, 32, 32, 32, 32, 32, 32, 32, 33, 33, 33, 12, 12, 33, 32, 32, 32, 28, 28, 28, 28, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, NA, NA, 32, 32, …
    $ qtype_name  <chr> "SRV", "NB", "NB", "NB", "NB", "NB", "NB", "NB", "NB", "NB", "SRV", "SRV", "SRV", "PTR", "PTR", "SRV", "NB", "NB", "NB", "AAAA", "AAAA", "AAA…
    $ rcode       <dbl> 0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,…
    $ rcode_name  <chr> "NOERROR", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "NOERROR", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-",…
    $ AA          <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, F…
    $ TC          <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, F…
    $ RD          <lgl> FALSE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TR…
    $ RA          <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, F…
    $ Z           <dbl> 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, …
    $ answers     <chr> "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "…
    $ TTLs        <chr> "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "…
    $ rejected    <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, F…

### 5. Сколько участников информационного обмена в сети Доброй Организации?

    > n_distinct(c(dns_data_clean$id.orig_h, dns_data_clean$id.resp_h))
    [1] 1359

### 6. Какое соотношение участников обмена внутри сети и участников обращений к внешним ресурсам?

    > internal_ips <- dns_data_clean$id.orig_h[grepl("^192\\.168|^10\\.|^172\\.", dns_data_clean$id.orig_h)]
    > external_ips <- dns_data_clean$id.orig_h[!grepl("^192\\.168|^10\\.|^172\\.", dns_data_clean$id.orig_h)]
    > ratio <- length(internal_ips) / length(external_ips)
    > ratio
    [1] 19.68718

### 7. Найдите топ-10 участников сети, проявляющих наибольшую сетевую активность.

    > dns_data_clean %>% count(id.orig_h, sort = TRUE) %>% head(10)
    # A tibble: 10 × 2
       id.orig_h           n
       <chr>           <int>
     1 10.10.117.210   75943
     2 192.168.202.93  26522
     3 192.168.202.103 18121
     4 192.168.202.76  16978
     5 192.168.202.97  16176
     6 192.168.202.141 14967
     7 10.10.117.209   14222
     8 192.168.202.110 13372
     9 192.168.203.63  12148
    10 192.168.202.106 10784

### 8. Найдите топ-10 доменов, к которым обращаются пользователи сети и соответственное количество обращений.

    > dns_data_clean %>% count(query, sort = TRUE) %>% head(10)
    # A tibble: 10 × 2
       query                                                                         n
       <chr>                                                                     <int>
     1 "teredo.ipv6.microsoft.com"                                               39273
     2 "tools.google.com"                                                        14057
     3 "www.apple.com"                                                           13390
     4 "time.apple.com"                                                          13109
     5 "safebrowsing.clients.google.com"                                         11658
     6 "*\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00" 10401
     7 "WPAD"                                                                     9134
     8 "44.206.168.192.in-addr.arpa"                                              7248
     9 "HPE8AA67"                                                                 6929
    10 "ISATAP"   

### 9. Определите базовые статистические характеристики интервала времени между последовательными обращениями к топ-10 доменам.

    > top_domains <- dns_data_clean %>% count(query, sort = TRUE) %>% head(10) %>% pull(query)
    > dns_data_clean %>%
    +     filter(query %in% top_domains) %>%
    +     arrange(query, ts) %>%
    +     group_by(query) %>%
    +     mutate(time_diff = as.numeric(ts - lag(ts))) %>%
    +     filter(!is.na(time_diff)) %>%
    +     summarise(
    +         requests_count = n() + 1,
    +         min_time = min(time_diff),
    +         median_time = median(time_diff), 
    +         mean_time = mean(time_diff),
    +         max_time = max(time_diff)
    +     )
    # A tibble: 10 × 6
       query                                                                     requests_count min_time median_time mean_time max_time
       <chr>                                                                              <dbl>    <dbl>       <dbl>     <dbl>    <dbl>
     1 "*\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"          10401        0       0.5       11.2    52724.
     2 "44.206.168.192.in-addr.arpa"                                                       7248        0       4         16.0    49680.
     3 "HPE8AA67"                                                                          6929        0       0.75      16.6    50044.
     4 "ISATAP"                                                                            6569        0       0.760     17.5    51998.
     5 "WPAD"                                                                              9134        0       0.75      12.6    50049.
     6 "safebrowsing.clients.google.com"                                                  11658        0       1         10.0    49952.
     7 "teredo.ipv6.microsoft.com"                                                        39273        0       0          2.94   50388.
     8 "time.apple.com"                                                                   13109        0       1.76       8.67   50924.
     9 "tools.google.com"                                                                 14057        0       0          8.19   50365.
    10 "www.apple.com"

### 10. Часто вредоносное программное обеспечение использует DNS канал в качестве канала управления, периодически отправляя запросы на подконтрольный злоумышленникам DNS сервер. По периодическим запросам на один и тот же домен можно выявить скрытый DNS канал. Есть ли такие IP адреса в исследуемом датасете?

    > suspicious_ips <- dns_data_clean %>%
    +     count(id.orig_h, query, sort = TRUE) %>%
    +     filter(n > 10) %>%  # частые запросы на один домен
    +     arrange(desc(n))
    > print(suspicious_ips)
    # A tibble: 3,015 × 3
       id.orig_h       query                           n
       <chr>           <chr>                       <int>
     1 10.10.117.210   teredo.ipv6.microsoft.com   27425
     2 192.168.202.93  www.apple.com               10852
     3 10.10.117.210   tools.google.com            10179
     4 192.168.202.83  44.206.168.192.in-addr.arpa  7248
     5 192.168.202.76  HPE8AA67                     6929
     6 192.168.202.93  time.apple.com               6038
     7 192.168.203.63  imap.gmail.com               5543
     8 192.168.202.76  WPAD                         5175
     9 192.168.202.103 api.twitter.com              4163
    10 192.168.202.103 api.facebook.com             4137
    # ℹ 3,005 more rows
    # ℹ Use `print(n = ...)` to see more rows

### 11. Определите местоположение (страну, город) и организацию-провайдера для топ-10 доменов.

    > get_geo_by_domain <- function(domain) {
    +     tryCatch({
    +         url <- paste0("http://ip-api.com/json/", domain)
    +         res <- GET(url)
    +         data <- fromJSON(content(res, "text", encoding = "UTF-8"))
    +         
    +         if (data$status == "success") {
    +             tibble(
    +                 domain = domain,
    +                 ip = data$query,
    +                 country = data$country,
    +                 city = data$city,
    +                 org = data$org
    +             )
    +         } else {
    +             tibble(domain = domain, ip = NA, country = NA, city = NA, org = NA)
    +         }
    +     }, error = function(e) tibble(domain = domain, ip = NA, country = NA, city = NA, org = NA))
    + }
    > 
    > esults <- top10_domains %>%
    +     pull(domain) %>%          # вытаскиваем вектор доменов
    +     map_dfr(get_geo_by_domain)
    > results <- top10_domains %>%
    +     pull(domain) %>%          # вытаскиваем вектор доменов
    +     map_dfr(get_geo_by_domain)
    > results <- results %>%
    +     left_join(top10_domains, by = "domain") %>%
    +     select(domain, n, ip, country, city, org)
    > print(results)
    # A tibble: 10 × 6
       domain                                                                        n ip                       country       city          org                
       <chr>                                                                     <int> <chr>                    <chr>         <chr>         <chr>              
     1 "teredo.ipv6.microsoft.com"                                               39273 NA                       NA            NA            NA                 
     2 "tools.google.com"                                                        14057 172.253.62.102           United States Mountain View Google LLC         
     3 "www.apple.com"                                                           13390 2600:1408:c400:88d::1aca United States Ashburn       Akamai Technologies
     4 "time.apple.com"                                                          13109 17.253.83.253            United States Los Angeles   Apple Inc          
     5 "safebrowsing.clients.google.com"                                         11658 142.250.72.174           United States Los Angeles   Google LLC         
     6 "*\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00" 10401 NA                       NA            NA            NA                 
     7 "WPAD"                                                                     9134 NA                       NA            NA            NA                 
     8 "44.206.168.192.in-addr.arpa"                                              7248 NA                       NA            NA            NA                 
     9 "HPE8AA67"                                                                 6929 NA                       NA            NA            NA                 
    10 "ISATAP"                                                                   6569 NA                       NA            NA            NA                 

## Оценка результатов и вывод

В ходе анализа DNS-логов было выявлено, что в сети Доброй Организации
присутствуют признаки подозрительной активности, включая периодические
DNS-запросы от определенных IP-адресов, что может свидетельствовать о
скрытых каналах управления вредоносного ПО.
