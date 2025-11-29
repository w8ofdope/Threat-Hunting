# Практическая работа 5. Исследование информации о состоянии
беспроводных сетей.
TrystNB@ya.ru

## Цель работы

1.  Получить знания о методах исследования радиоэлектронной обстановки.
2.  Составить представление о механизмах работы Wi-Fi сетей на канальном
    и сетевом уровне модели OSI.
3.  Зекрепить практические навыки использования языка программирования R
    для обработки данных.
4.  Закрепить знания основных функций обработки данных экосистемы
    tidyverse языка R.

## Исходные данные

1.  Оепрационная система Windows 11
2.  RStudio
3.  Интерпретатор языка R

## Задание

Используя программный пакет dplyr языка программирования R провести
анализ журналов и ответить на вопросы.

## Впоросы

**Подготовка данных:**

1.  Импортировать данные из CSV-файла, учитывая особенности формата лога
    airodump-ng
2.  Разделить данные на два датасета: точки доступа и клиенты
3.  Привести датасеты в вид “аккуратных данных”, преобразовать типы
    столбцов в соответствии с типом данных
4.  Просмотреть общую структуру данных с помощью функции glimpse()

**Анализ точек доступа:**

1.  Определить небезопасные точки доступа (без шифрования – OPN)
2.  Определить производителя для каждого обнаруженного устройства по OUI
3.  Выявить устройства, использующие протокол шифрования WPA3
4.  Отсортировать точки доступа по времени нахождения на связи (со
    склейкой сессий)
5.  Обнаружить топ-10 самых быстрых точек доступа
6.  Отсортировать точки доступа по частоте отправки beacon-запросов

**Анализ клиентов:**

1.  Определить производителя для каждого клиентского устройства по OUI
2.  Обнаружить устройства, которые не рандомизируют свой MAC-адрес
3.  Кластеризовать запросы от устройств к точкам доступа
4.  Определить время появления и выхода устройств из зоны радиовидимости
5.  Оценить стабильность уровня сигнала внутри кластеров и выявить
    наиболее стабильный

## Выполнение задания

``` r
sessionInfo()
```

    R version 4.5.1 (2025-06-13 ucrt)
    Platform: x86_64-w64-mingw32/x64
    Running under: Windows 11 x64 (build 26100)

    Matrix products: default
      LAPACK version 3.12.1

    locale:
    [1] LC_COLLATE=Russian_Russia.utf8  LC_CTYPE=Russian_Russia.utf8   
    [3] LC_MONETARY=Russian_Russia.utf8 LC_NUMERIC=C                   
    [5] LC_TIME=Russian_Russia.utf8    

    time zone: Europe/Moscow
    tzcode source: internal

    attached base packages:
    [1] stats     graphics  grDevices utils     datasets  methods   base     

    loaded via a namespace (and not attached):
     [1] compiler_4.5.1    fastmap_1.2.0     cli_3.6.5         tools_4.5.1      
     [5] htmltools_0.5.8.1 rstudioapi_0.17.1 yaml_2.3.10       rmarkdown_2.30   
     [9] knitr_1.50        jsonlite_2.0.0    xfun_0.53         digest_0.6.37    
    [13] rlang_1.1.6       evaluate_1.0.5   

### 1. Импортировать данные из CSV-файла, учитывая особенности формата лога airodump-ng

    > library(tidyverse)
    > library(lubridate)
    > library(readr)
    > setwd("PR_5")
    > raw_data <- read_csv("P2_wifi_data.csv", skip = 1, col_names = FALSE, show_col_types = FALSE)
    > cat("Размеры сырых данных:", dim(raw_data), "\n")
    Размеры сырых данных: 12250 15 
    > cat("Первые 3 строки сырых данных:\n")
    Первые 3 строки сырых данных:
    > print(head(raw_data, 3))
    # A tibble: 3 × 15
      X1                X2                  X3                  X4      X5    X6      X7     X8             X9    X10       X11   X12           X13       X14          X15  
      <chr>             <chr>               <chr>               <chr>   <chr> <chr>   <chr>  <chr>          <chr> <chr>     <chr> <chr>         <chr>     <chr>        <chr>
    1 BSSID             First time seen     Last time seen      channel Speed Privacy Cipher Authentication Power # beacons # IV  LAN IP        ID-length ESSID        Key  
    2 BE:F1:71:D5:17:8B 2023-07-28 09:13:03 2023-07-28 11:50:50 1       195   WPA2    CCMP   PSK            -30   846       504   0.  0.  0.  0 12        C322U13 3965 NA   
    3 6E:C7:EC:16:DA:1A 2023-07-28 09:13:03 2023-07-28 11:55:12 1       130   WPA2    CCMP   PSK            -30   750       116   0.  0.  0.  0 4         Cnet         NA   
    > 

### 2. Разделить данные на два датасета: точки доступа и клиенты

    ap_data <- raw_data[1:(empty_row-1), ] %>% filter(X1 != "BSSID") %>% .[, 1:10]
    names(ap_data) <- c("BSSID", "First_time_seen", "Last_time_seen", "channel", "Speed", "Privacy", "Cipher", "Authentication", "Power", "beacons")

    client_data <- raw_data[empty_row:nrow(raw_data), ] %>% filter(X1 != "Station MAC") %>% .[, 1:7]
    names(client_data) <- c("Station_MAC", "First_time_seen", "Last_time_seen", "Power", "packets", "BSSID", "Probed_ESSIDs")

    ap_data <- ap_data %>% mutate(
      First_time_seen = as_datetime(First_time_seen),
      Last_time_seen = as_datetime(Last_time_seen),
      Power = as.numeric(Power),
      beacons = as.numeric(beacons)
    )

    client_data <- client_data %>% mutate(
      First_time_seen = as_datetime(First_time_seen),
      Last_time_seen = as_datetime(Last_time_seen),
      Power = as.numeric(Power),
      packets = as.numeric(packets)
    )

    cat("Точки доступа:", nrow(ap_data), "Клиенты:", nrow(client_data))

### 3. Просмотреть общую структуру данных с помощью функции glimpse()

    > glimpse(ap_data)
    Rows: 167
    Columns: 10
    $ BSSID           <chr> "BE:F1:71:D5:17:8B", "6E:C7:EC:16:DA:1A", "9A:75:A8:B9:04:1E", "4A:EC:1E:DB:BF:95", "D2:6D:52:61:51:5D", "E8:28:C1:DC:B2:52", "BE:F1:71:D6:10:D7", "0A:C5:E1:DB:17:7B", "38:1A:52:0D:84:D7", "BE:F1:71:D5:0E:5…
    $ First_time_seen <dttm> 2023-07-28 09:13:03, 2023-07-28 09:13:03, 2023-07-28 09:13:03, 2023-07-28 09:13:03, 2023-07-28 09:13:03, 2023-07-28 09:13:03, 2023-07-28 09:13:03, 2023-07-28 09:13:03, 2023-07-28 09:13:03, 2023-07-28 09:13…
    $ Last_time_seen  <dttm> 2023-07-28 11:50:50, 2023-07-28 11:55:12, 2023-07-28 11:53:31, 2023-07-28 11:04:01, 2023-07-28 10:30:19, 2023-07-28 11:55:38, 2023-07-28 11:50:44, 2023-07-28 11:36:31, 2023-07-28 10:25:02, 2023-07-28 10:29…
    $ channel         <chr> "1", "1", "1", "7", "6", "6", "11", "11", "11", "1", "6", "14", "11", "11", "6", "6", "6", "6", "44", "1", "1", "1", "3", "11", "6", "6", "14", "14", "1", "11", "14", "1", "11", "11", "11", "44", "1", "14",…
    $ Speed           <chr> "195", "130", "360", "360", "130", "130", "195", "130", "130", "195", "180", "65", "130", "130", "130", "130", "65", "-1", "-1", "54", "270", "54", "270", "130", "130", "130", "65", "65", "130", "54", "-1",…
    $ Privacy         <chr> "WPA2", "WPA2", "WPA2", "WPA2", "WPA2", "OPN", "WPA2", "WPA2", "WPA2", "WPA2", "WPA2", "WPA2", "WPA2", "WPA2", "OPN", "OPN", "WPA2", "OPN", "OPN", "WPA2", "WPA2", "WPA2", "WPA2", "OPN", "OPN", "OPN", "WPA2"…
    $ Cipher          <chr> "CCMP", "CCMP", "CCMP", "CCMP", "CCMP", NA, "CCMP", "CCMP", "CCMP", "CCMP", "CCMP", "CCMP", "CCMP", "CCMP", NA, NA, "CCMP", NA, NA, "CCMP", "CCMP", "CCMP", "CCMP", NA, NA, NA, "CCMP", "CCMP", NA, "CCMP", NA…
    $ Authentication  <chr> "PSK", "PSK", "PSK", "PSK", "PSK", NA, "PSK", "PSK", "PSK", "PSK", "PSK", "PSK", "PSK", "PSK", NA, NA, "PSK", NA, NA, "PSK", "PSK", "PSK", "PSK", NA, NA, NA, "PSK", "PSK", NA, "PSK", NA, "PSK", NA, NA, "PSK…
    $ Power           <dbl> -30, -30, -68, -37, -57, -63, -27, -38, -38, -66, -42, -62, -73, -69, -63, -63, -51, -1, -1, -65, -61, -65, -65, -67, -82, -69, -61, -74, -69, -70, -1, -72, -78, -73, -82, -85, -71, -81, -78, -72, -64, -70,…
    $ beacons         <dbl> 846, 750, 694, 510, 647, 251, 1647, 1251, 704, 617, 1390, 142, 28, 112, 260, 279, 248, 0, 0, 84, 109, 65, 42, 4, 2, 1, 51, 40, 12, 61, 0, 7, 20, 9, 0, 3, 7, 9, 0, 19, 317, 22, 0, 32, 0, 5, 5, 0, 47, 46, 5, …
    > glimpse(client_data)
    Rows: 12,081
    Columns: 7
    $ Station_MAC     <chr> "CA:66:3B:8F:56:DD", "96:35:2D:3D:85:E6", "5C:3A:45:9E:1A:7B", "C0:E4:34:D8:E7:E5", "5E:8E:A6:5E:34:81", "10:51:07:CB:33:E7", "68:54:5A:40:35:9E", "74:4C:A1:70:CE:F7", "8A:A3:5A:33:76:57", "CA:54:C4:8B:B5:3…
    $ First_time_seen <dttm> 2023-07-28 09:13:03, 2023-07-28 09:13:03, 2023-07-28 09:13:03, 2023-07-28 09:13:03, 2023-07-28 09:13:04, 2023-07-28 09:13:05, 2023-07-28 09:13:06, 2023-07-28 09:13:06, 2023-07-28 09:13:06, 2023-07-28 09:13…
    $ Last_time_seen  <dttm> 2023-07-28 10:59:44, 2023-07-28 09:13:03, 2023-07-28 11:51:54, 2023-07-28 11:53:16, 2023-07-28 09:13:04, 2023-07-28 11:56:06, 2023-07-28 11:50:50, 2023-07-28 09:20:01, 2023-07-28 10:20:27, 2023-07-28 11:55…
    $ Power           <dbl> -33, -65, -39, -61, -53, -43, -31, -71, -74, -65, -45, -65, -49, -1, -67, -37, -69, -55, -57, -57, -75, -43, -29, -48, -53, -37, -51, -51, -57, -55, -33, -41, -67, -35, -65, -43, -43, -31, -29, -53, -43, -2…
    $ packets         <dbl> 858, 4, 432, 958, 1, 344, 163, 3, 115, 437, 265, 77, 7, 71, 1, 125, 2245, 4096, 849, 179, 2, 332, 667, 122, 6, 156, 1, 1, 2, 2, 8171, 6, 3, 675, 117, 1, 1, 606, 240, 4, 76, 539, 2, 165, 617, 463, 22, 1, 1, …
    $ BSSID           <chr> "BE:F1:71:D5:17:8B", "(not associated)", "BE:F1:71:D6:10:D7", "BE:F1:71:D5:17:8B", "(not associated)", "(not associated)", "1E:93:E3:1B:3C:F4", "E8:28:C1:DC:FF:F2", "00:25:00:FF:94:73", "00:26:99:F2:7A:E2",…
    $ Probed_ESSIDs   <chr> "C322U13 3965", "IT2 Wireless", "C322U21 0566", "C322U13 3965", NA, NA, "C322U06 5179", NA, NA, "GIVC", NA, "KOTIKI_XXX", NA, NA, NA, "AndroidAP177B", "nvripcsuite", "nvripcsuite", NA, NA, NA, NA, NA, "Gala…

### 4. Определить небезопасные точки доступа (без шифрования – OPN)

    > ap_data %>% filter(Privacy == "OPN") %>% select(BSSID, Privacy)
    # A tibble: 42 × 2
       BSSID             Privacy
       <chr>             <chr>  
     1 E8:28:C1:DC:B2:52 OPN    
     2 E8:28:C1:DC:B2:50 OPN    
     3 E8:28:C1:DC:B2:51 OPN    
     4 E8:28:C1:DC:FF:F2 OPN    
     5 00:25:00:FF:94:73 OPN    
     6 E8:28:C1:DD:04:52 OPN    
     7 E8:28:C1:DE:74:31 OPN    
     8 E8:28:C1:DE:74:32 OPN    
     9 E8:28:C1:DC:C8:32 OPN    
    10 E8:28:C1:DD:04:50 OPN 

### 5. Определить производителя для каждого обнаруженного устройства по OUI

    > get_oui <- function(mac) str_sub(mac, 1, 8) %>% str_replace_all(":", "-")
    > ap_data %>% mutate(OUI = map_chr(BSSID, get_oui)) %>% distinct(BSSID, OUI)
    # A tibble: 167 × 2
       BSSID             OUI     
       <chr>             <chr>   
     1 BE:F1:71:D5:17:8B BE-F1-71
     2 6E:C7:EC:16:DA:1A 6E-C7-EC
     3 9A:75:A8:B9:04:1E 9A-75-A8
     4 4A:EC:1E:DB:BF:95 4A-EC-1E
     5 D2:6D:52:61:51:5D D2-6D-52
     6 E8:28:C1:DC:B2:52 E8-28-C1
     7 BE:F1:71:D6:10:D7 BE-F1-71
     8 0A:C5:E1:DB:17:7B 0A-C5-E1
     9 38:1A:52:0D:84:D7 38-1A-52
    10 BE:F1:71:D5:0E:53 BE-F1-71

### 6. Выявить устройства, использующие протокол шифрования WPA3

    > ap_data %>% filter(str_detect(toupper(Privacy), "WPA3") | str_detect(toupper(Authentication), "WPA3"))
    # A tibble: 8 × 10
      BSSID             First_time_seen     Last_time_seen      channel Speed Privacy   Cipher Authentication Power beacons
      <chr>             <dttm>              <dttm>              <chr>   <chr> <chr>     <chr>  <chr>          <dbl>   <dbl>
    1 26:20:53:0C:98:E8 2023-07-28 09:15:45 2023-07-28 09:33:10 44      866   WPA3 WPA2 CCMP   SAE PSK          -85       3
    2 A2:FE:FF:B8:9B:C9 2023-07-28 09:41:52 2023-07-28 09:41:52 6       130   WPA3 WPA2 CCMP   SAE PSK          -70       1
    3 96:FF:FC:91:EF:64 2023-07-28 09:52:54 2023-07-28 10:25:02 44      866   WPA3 WPA2 CCMP   SAE PSK          -85       9
    4 CE:48:E7:86:4E:33 2023-07-28 09:59:20 2023-07-28 10:04:15 44      866   WPA3 WPA2 CCMP   SAE PSK          -65       9
    5 8E:1F:94:96:DA:FD 2023-07-28 10:08:32 2023-07-28 10:15:27 44      866   WPA3 WPA2 CCMP   SAE PSK          -67      12
    6 BE:FD:EF:18:92:44 2023-07-28 10:15:24 2023-07-28 10:15:28 6       130   WPA3 WPA2 CCMP   SAE PSK          -64       0
    7 3A:DA:00:F9:0C:02 2023-07-28 10:27:01 2023-07-28 10:27:10 6       130   WPA3 WPA2 CCMP   SAE PSK          -65       5
    8 76:C5:A0:70:08:96 2023-07-28 11:16:36 2023-07-28 11:16:38 6       130   WPA3 WPA2 CCMP   SAE PSK          -52       1

### 7. Отсортировать точки доступа по времени нахождения на связи (со склейкой сессий)

    > ap_data %>% 
    +     mutate(duration = as.numeric(difftime(Last_time_seen, First_time_seen, units = "mins"))) %>%
    +     arrange(BSSID, First_time_seen) %>%
    +     group_by(BSSID) %>%
    +     mutate(time_gap = as.numeric(difftime(First_time_seen, lag(Last_time_seen), units = "mins")),
    +            new_session = ifelse(is.na(time_gap) | time_gap > 45, 1, 0),
    +            session_id = cumsum(new_session)) %>%
    +     group_by(BSSID, session_id) %>%
    +     summarise(total_duration = sum(duration), .groups = "drop") %>%
    +     arrange(desc(total_duration)) %>%
    +     print(n = 25)
    # A tibble: 167 × 3
       BSSID             session_id total_duration
       <chr>                  <dbl>          <dbl>
     1 00:25:00:FF:94:73          1           163.
     2 E8:28:C1:DD:04:52          1           163.
     3 E8:28:C1:DC:B2:52          1           163.
     4 08:3A:2F:56:35:FE          1           162.
     5 6E:C7:EC:16:DA:1A          1           162.
     6 E8:28:C1:DC:B2:50          1           162.
     7 48:5B:39:F9:7A:48          1           162.
     8 E8:28:C1:DC:B2:51          1           162.
     9 E8:28:C1:DC:FF:F2          1           162.
    10 8E:55:4A:85:5B:01          1           162.
    11 00:26:99:BA:75:80          1           162.
    12 00:26:99:F2:7A:E2          1           162.
    13 1E:93:E3:1B:3C:F4          1           161.
    14 0C:80:63:A9:6E:EE          1           160.
    15 9A:75:A8:B9:04:1E          1           160.
    16 00:23:EB:E3:81:F2          1           160.
    17 9E:A3:A9:DB:7E:01          1           159.
    18 E8:28:C1:DC:C8:32          1           159.
    19 1C:7E:E5:8E:B7:DE          1           159.
    20 00:26:99:F2:7A:E1          1           158.
    21 BE:F1:71:D5:17:8B          1           158.
    22 BE:F1:71:D6:10:D7          1           158.
    23 9E:A3:A9:D6:28:3C          1           158.
    24 E8:28:C1:DD:04:40          1           157.
    25 E8:28:C1:DD:04:41          1           157.
    # ℹ 142 more rows

### 8. Обнаружить топ-10 самых быстрых точек доступа

    > ap_data %>% 
    +     mutate(Speed = as.numeric(Speed)) %>%
    +     distinct(BSSID, .keep_all = TRUE) %>%
    +     arrange(desc(Speed)) %>%
    +     head(10) %>%
    +     select(BSSID, Speed)
    # A tibble: 10 × 2
       BSSID             Speed
       <chr>             <dbl>
     1 26:20:53:0C:98:E8   866
     2 96:FF:FC:91:EF:64   866
     3 CE:48:E7:86:4E:33   866
     4 8E:1F:94:96:DA:FD   866
     5 9A:75:A8:B9:04:1E   360
     6 4A:EC:1E:DB:BF:95   360
     7 56:C5:2B:9F:84:90   360
     8 E8:28:C1:DC:B2:41   360
     9 E8:28:C1:DC:B2:40   360
    10 E8:28:C1:DC:B2:42   360

### 10. Отсортировать точки доступа по частоте отправки beacon-запросов

    > ap_data %>%
    +     mutate(connection_time = as.numeric(difftime(Last_time_seen, First_time_seen, units = "hours")),
    +            beacon_rate = ifelse(connection_time > 0, beacons / connection_time, 0)) %>%
    +     filter(beacon_rate > 0) %>%
    +     distinct(BSSID, .keep_all = TRUE) %>%
    +     arrange(desc(beacon_rate)) %>%
    +     select(BSSID, beacon_rate)
    # A tibble: 89 × 2
       BSSID             beacon_rate
       <chr>                   <dbl>
     1 F2:30:AB:E9:03:ED       3086.
     2 B2:CF:C0:00:4A:60       2880 
     3 3A:DA:00:F9:0C:02       2000 
     4 02:BC:15:7E:D5:DC       1800 
     5 00:3E:1A:5D:14:45       1800 
     6 76:C5:A0:70:08:96       1800 
     7 D2:25:91:F6:6C:D8       1385.
     8 BE:F1:71:D6:10:D7        627.
     9 00:03:7A:1A:03:56        600 
    10 38:1A:52:0D:84:D7        587.

### 11. Определить производителя для каждого клиентского устройства по OUI

    > client_data %>% mutate(OUI = map_chr(Station_MAC, get_oui)) %>% distinct(Station_MAC, OUI)
    # A tibble: 12,081 × 2
       Station_MAC       OUI     
       <chr>             <chr>   
     1 CA:66:3B:8F:56:DD CA-66-3B
     2 96:35:2D:3D:85:E6 96-35-2D
     3 5C:3A:45:9E:1A:7B 5C-3A-45
     4 C0:E4:34:D8:E7:E5 C0-E4-34
     5 5E:8E:A6:5E:34:81 5E-8E-A6
     6 10:51:07:CB:33:E7 10-51-07
     7 68:54:5A:40:35:9E 68-54-5A
     8 74:4C:A1:70:CE:F7 74-4C-A1
     9 8A:A3:5A:33:76:57 8A-A3-5A
    10 CA:54:C4:8B:B5:3A CA-54-C4
    # ℹ 12,071 more rows

### 12. Обнаружить устройства, которые не рандомизируют свой MAC-адрес

    > fastest_aps <- ap_data %>%
    +     mutate(Speed = as.numeric(Speed)) %>%
    +     filter(!is.na(Speed)) %>%
    +     arrange(desc(Speed)) %>%
    +     slice(1:10)
    > select(fastest_aps, BSSID, Speed)
    # A tibble: 10 × 2
       BSSID             Speed
       <chr>             <dbl>
     1 26:20:53:0C:98:E8   866
     2 96:FF:FC:91:EF:64   866
     3 CE:48:E7:86:4E:33   866
     4 8E:1F:94:96:DA:FD   866
     5 9A:75:A8:B9:04:1E   360
     6 4A:EC:1E:DB:BF:95   360
     7 56:C5:2B:9F:84:90   360
     8 E8:28:C1:DC:B2:41   360
     9 E8:28:C1:DC:B2:40   360
    10 E8:28:C1:DC:B2:42   360

### 13. Кластеризовать запросы от устройств к точкам доступа

    > clusters <- client_data %>%
    +     group_by(Station_MAC, Probed_ESSIDs) %>%
    +     summarise(cluster_size = n(), .groups = "drop") %>%
    +     arrange(desc(cluster_size))
    > clusters
    # A tibble: 12,081 × 3
       Station_MAC       Probed_ESSIDs cluster_size
       <chr>             <chr>                <int>
     1 00:04:35:22:4F:75 NA                       1
     2 00:0C:E7:A8:D6:73 NA                       1
     3 00:90:4C:E6:54:54 Redmi                    1
     4 00:95:69:E7:7C:ED nvripcsuite              1
     5 00:95:69:E7:7D:21 nvripcsuite              1
     6 00:95:69:E7:7F:35 nvripcsuite              1
     7 00:98:8C:CE:8E:45 NA                       1
     8 00:E9:3A:67:93:E9 NA                       1
     9 00:E9:3A:F8:10:C7 NA                       1
    10 00:F4:8D:F7:C5:19 Redmi 12                 1
    # ℹ 12,071 more rows

### 14. Определить время появления и выхода устройств из зоны радиовидимости

    > device_visibility <- client_data %>%
    +     group_by(Station_MAC) %>%
    +     summarise(
    +         first_appearance = min(First_time_seen),
    +         last_appearance = max(Last_time_seen),
    +         total_time = as.numeric(difftime(max(Last_time_seen), min(First_time_seen), units = "mins")),
    +         .groups = "drop"
    +     ) %>%
    +     arrange(desc(total_time))
    > device_visibility
    # A tibble: 12,081 × 4
       Station_MAC       first_appearance    last_appearance     total_time
       <chr>             <dttm>              <dttm>                   <dbl>
     1 10:51:07:CB:33:BF 2023-07-28 09:13:13 2023-07-28 11:56:17       163.
     2 00:95:69:E7:7C:ED 2023-07-28 09:13:11 2023-07-28 11:56:13       163.
     3 00:95:69:E7:7D:21 2023-07-28 09:13:15 2023-07-28 11:56:17       163.
     4 10:51:07:CB:33:E7 2023-07-28 09:13:05 2023-07-28 11:56:06       163.
     5 8C:55:4A:DE:F2:38 2023-07-28 09:13:17 2023-07-28 11:56:16       163.
     6 00:95:69:E7:7F:35 2023-07-28 09:13:11 2023-07-28 11:56:07       163.
     7 BC:F1:71:D5:3F:C7 2023-07-28 09:13:24 2023-07-28 11:55:58       163.
     8 10:51:07:FE:77:C0 2023-07-28 09:13:27 2023-07-28 11:55:53       162.
     9 BC:F1:71:D5:0E:71 2023-07-28 09:13:38 2023-07-28 11:56:02       162.
    10 70:66:55:D0:B6:C7 2023-07-28 09:14:09 2023-07-28 11:56:21       162.
    # ℹ 12,071 more rows

### 15.

    > signal_stability <- client_data %>%
    +     filter(BSSID != "(not associated)", !is.na(Power)) %>%
    +     group_by(BSSID) %>%
    +     summarise(
    +         average_power = mean(Power, na.rm = TRUE),
    +         power_variation = sd(Power, na.rm = TRUE),
    +         observations = n(),
    +         .groups = 'drop'
    +     ) %>%
    +     arrange(power_variation)
    > signal_stability
    # A tibble: 74 × 4
       BSSID             average_power power_variation observations
       <chr>                     <dbl>           <dbl>        <int>
     1 86:DF:BF:E4:2F:23         -71              0               2
     2 E8:28:C1:DC:C8:32          -1              0               2
     3 E8:28:C1:DC:FF:F2         -73              2               3
     4 CE:B3:FF:84:45:FC         -85              2.83            2
     5 E8:28:C1:DD:04:40         -61              2.83            2
     6 8E:55:4A:85:5B:01         -50.3            4.13            6
     7 00:26:99:F2:7A:E2         -64.2            4.40            8
     8 E8:28:C1:DC:B2:50         -59.8            5.22            5
     9 E8:28:C1:DC:F0:90         -63.7            6.11            3
    10 00:25:00:FF:94:73         -71.2            6.51           45
    # ℹ 64 more rows

## Оценка результатов и вывод

В ходе анализа Wi-Fi трафика выявлены точки доступа без шифрования
(OPN), что создает риски для безопасности сети. Определены производители
устройств по OUI, обнаружены самые быстрые и активные точки доступа.
Проанализировано поведение клиентских устройств, выявлены устройства с
постоянными MAC-адресами. Оценена стабильность сигнала соединений.
