# Практическая работа 6. Исследование вредоносной активности в домене
Windows.
TrystNB@ya.ru

## Цель работы

1.  Закрепить навыки исследования данных журнала Windows Active
    Directory.
2.  Изучить структуру журнала системы Windows Active Directory.
3.  Зекрепить практические навыки использования языка программирования R
    для обработки данных.
4.  Закрепить знания основных функций обработки данных экосистемы
    tidyverse языка R.

## Исходные данные

1.  Оепрационная система Windows 11
2.  RStudio
3.  Интерпретатор языка R

## Задание

На протяжении долгого времени системные администраторы Доброй
Организации замечали подозрительную активность в домене Windows, но
конкретных доказательств компрометации сети найти не удавалось. К Вам в
руки попал файл с выгрузкой данных из системы SIEM. Помогите выявить
факты компрометации.Используя программный пакет dplyr
языкапрограммирования R провести анализ журналов и ответить на вопросы.

## Впоросы

**Подготовка данных:**

1.  Импортировать данные из JSON-файла с помощью
    `jsonlite::stream_in(file())`
2.  Импортировать справочник кодов событий Windows с веб-страницы
    Microsoft
3.  Привести датасеты в вид “аккуратных данных”, преобразовать типы
    столбцов
4.  Просмотреть общую структуру данных с помощью функции `glimpse()`

**Анализ данных:**

1.  Раскрыть вложенные датафреймы с помощью `tidyr::unnest()`
2.  Убрать колонки с единственным значением параметра
3.  Определить количество хостов в датасете
4.  Подготовить датафрейм с расшифровкой Windows Event_ID
5.  Определить наличие событий с высоким и средним уровнем значимости и
    их количество

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

### 1. Импортировать данные из JSON-файла с помощью jsonlite::stream_in(file())

    > library(jsonlite)
    > library(xml2)
    > library(rvest)
    > 
    > data_url <- "https://storage.yandexcloud.net/iamcth-data/dataset.tar.gz"
    > local_file <- "dataset.tar.gz"
    > download.file(url = data_url, destfile = local_file, mode = "wb", quiet = TRUE)
    > archive_files <- untar(tarfile = local_file, list = TRUE)
    > json_filename <- archive_files[grep("\\.json$", archive_files)]
    > temp_dir <- tempdir()
    > untar(tarfile = local_file, files = json_filename, exdir = temp_dir)
    > json_path <- file.path(temp_dir, json_filename)
    > json_connection <- file(json_path, open = "r")
    > imported_data <- stream_in(json_connection)
     Imported 101904 records. Simplifying...
    > 
    > webpage <- read_html("https://learn.microsoft.com/en-us/windows-server/identity/adds/plan/appendix-l--events-to-monitor")

    > glimpse(imported_data)
    Rows: 101,904
    Columns: 9
    $ `@timestamp` <chr> "2019-10-20T20:11:06.937Z", "2019-10-20T20:11:07.101Z", "2019-10-20T20:11:09.052Z", "2019-10-20T20:11:10.985Z", "2019-10-20T20:11:11.249Z", "2019-10-20T20:11:15.017Z", "2019-10-20T20:11:15.438Z", "2019-10-20T2…
    $ `@metadata`  <df[,4]> <data.frame[77 x 4]>
    $ event        <df[,4]> <data.frame[77 x 4]>
    $ log          <df[,1]> <data.frame[77 x 1]>
    $ message      <chr> "A token right was adjusted.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tHR001$\n\tAccount Domain:\t\tshire\n\tLogon ID:\t\t0x3E7\n\nTarget Account:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Na…
    $ winlog       <df[,16]> <data.frame[77 x 16]>
    $ ecs          <df[,1]> <data.frame[77 x 1]>
    $ host         <df[,1]> <data.frame[77 x 1]>
    $ agent        <df[,5]> <data.frame[77 x 5]>

### 2. Импортировать справочник кодов событий Windows с веб-страницы Microsoft

    library(xml2)
    library(rvest)

    # Пробуем загрузить справочник событий Windows
    tryCatch({
      webpage <- read_html("https://learn.microsoft.com/en-us/windows-server/identity/adds/plan/appendix-l--events-to-monitor")
      event_df <- html_table(webpage)[[1]]
      cat("Справочник событий импортирован:", nrow(event_df), "записей\n")
    }, error = function(e) {
      event_df <- data.frame(
        `Event ID` = c(4624, 4625, 4672, 4720, 4732),
        `Event source` = "Microsoft-Windows-Security-Auditing",
        `Event description` = c("Успешный вход", "Неудачный вход", "Привилегии", "Создание учетной записи", "Изменение группы"),
        `Event severity` = c("Information", "Warning", "Information", "Information", "Information")
      )
    })

### 3. Привести датасеты в вид “аккуратных данных”, преобразовать типы столбцов

    > imported_clean <- imported_data %>%
    +     mutate(
    +         timestamp = as.POSIXct(`@timestamp`, format = "%Y-%m-%dT%H:%M:%OSZ"),
    +         across(where(is.character), ~na_if(., ""))
    +     )
    > 
    > # Раскрываем вложенные колонки
    > for(col in names(imported_clean)) {
    +     if(is.data.frame(imported_clean[[col]])) {
    +         imported_clean <- imported_clean %>%
    +             unnest(all_of(col), names_sep = "_")
    +     }
    + }
    > 
    > event_clean <- event_df %>%
    +     mutate(across(where(is.character), ~na_if(., "")))
    > 
    > cat("Данные преобразованы. Записей:", nrow(imported_clean), "Колонок:", ncol(imported_clean))
    Данные преобразованы. Записей: 101904 Колонок: 35

### 4. Просмотреть общую структуру данных с помощью функции glimpse()

    > glimpse(imported_clean)
    Rows: 101,904
    Columns: 35
    $ `@timestamp`         <chr> "2019-10-20T20:11:06.937Z", "2019-10-20T20:11:07.101Z", "2019-10-20T20:11:09.052Z", "2019-10-20T20:11:10.985Z", "2019-10-20T20:11:11.249Z", "2019-10-20T20:11:15.017Z", "2019-10-20T20:11:15.438Z", "2019…
    $ `@metadata_beat`     <chr> "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winl…
    $ `@metadata_type`     <chr> "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "_doc", "…
    $ `@metadata_version`  <chr> "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.…
    $ `@metadata_topic`    <chr> "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winl…
    $ event_created        <chr> "2019-10-20T20:11:09.988Z", "2019-10-20T20:11:09.988Z", "2019-10-20T20:11:11.995Z", "2019-10-20T20:11:14.013Z", "2019-10-20T20:11:14.013Z", "2019-10-20T20:11:18.027Z", "2019-10-20T20:11:18.027Z", "2019…
    $ event_kind           <chr> "event", "event", "event", "event", "event", "event", "event", "event", "event", "event", "event", "event", "event", "event", "event", "event", "event", "event", "event", "event", "event", "event", "ev…
    $ event_code           <int> 4703, 4673, 10, 10, 10, 10, 11, 10, 10, 10, 10, 7, 7, 7, 4689, 10, 5, 4703, 10, 10, 10, 10, 5158, 5156, 5156, 4672, 4624, 4627, 4634, 12, 12, 3, 3, 10, 10, 7, 7, 7, 10, 10, 10, 10, 10, 10, 10, 7, 10, 5…
    $ event_action         <chr> "Token Right Adjusted Events", "Sensitive Privilege Use", "Process accessed (rule: ProcessAccess)", "Process accessed (rule: ProcessAccess)", "Process accessed (rule: ProcessAccess)", "Process accessed…
    $ log_level            <chr> "information", "information", "information", "information", "information", "information", "information", "information", "information", "information", "information", "information", "information", "infor…
    $ message              <chr> "A token right was adjusted.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tHR001$\n\tAccount Domain:\t\tshire\n\tLogon ID:\t\t0x3E7\n\nTarget Account:\n\tSecurity ID:\t\tS-1-5-18\n\tAccou…
    $ winlog_event_data    <df[,234]> <data.frame[77 x 234]>
    $ winlog_event_id      <int> 4703, 4673, 10, 10, 10, 10, 11, 10, 10, 10, 10, 7, 7, 7, 4689, 10, 5, 4703, 10, 10, 10, 10, 5158, 5156, 5156, 4672, 4624, 4627, 4634, 12, 12, 3, 3, 10, 10, 7, 7, 7, 10, 10, 10, 10, 10, 10, 10, 7, …
    $ winlog_provider_name <chr> "Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon", "Microsoft-…
    $ winlog_api           <chr> "wineventlog", "wineventlog", "wineventlog", "wineventlog", "wineventlog", "wineventlog", "wineventlog", "wineventlog", "wineventlog", "wineventlog", "wineventlog", "wineventlog", "wineventlog", "winev…
    $ winlog_record_id     <int> 50588, 104875, 226649, 153525, 163488, 153526, 134651, 226650, 226651, 226652, 226653, 162367, 162368, 162369, 26042, 226654, 226655, 22614, 134652, 134653, 134654, 226656, 104876, 104877, 104878, 1048…
    $ winlog_computer_name <chr> "HR001.shire.com", "HFDC01.shire.com", "IT001.shire.com", "HR001.shire.com", "ACCT001.shire.com", "HR001.shire.com", "FILE001.shire.com", "IT001.shire.com", "IT001.shire.com", "IT001.shire.com", "IT001…
    $ winlog_process       <df[,2]> <data.frame[77 x 2]>
    $ winlog_keywords      <list> "Audit Success", "Audit Failure", <NULL>, <NULL>, <NULL>, <NULL>, <NULL>, <NULL>, <NULL>, <NULL>, <NULL>, <NULL>, <NULL>, <NULL>, "Audit Success", <NULL>, <NULL>, "Audit Success", <NULL>, <NULL>, <NULL…
    $ winlog_provider_guid <chr> "{54849625-5478-4994-a5ba-3e3b0328c30d}", "{54849625-5478-4994-a5ba-3e3b0328c30d}", "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "{5770385f-c22a-43e0-bf4c-06f5…
    $ winlog_channel       <chr> "security", "Security", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windo…
    $ winlog_task          <chr> "Token Right Adjusted Events", "Sensitive Privilege Use", "Process accessed (rule: ProcessAccess)", "Process accessed (rule: ProcessAccess)", "Process accessed (rule: ProcessAccess)", "Process accessed…
    $ winlog_opcode        <chr> "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "Info", "…
    $ winlog_version       <int> NA, NA, 3, 3, 3, 3, 2, 3, 3, 3, 3, 3, 3, 3, NA, 3, 3, NA, 3, 3, 3, 3, NA, 1, 1, NA, 2, NA, NA, 2, 2, 5, 5, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, NA, 1, NA, 1, NA, 3, 1, 3, 5, 3, NA, NA, NA, 1, NA, …
    $ winlog_user          <df[,4]> <data.frame[77 x 4]>
    $ winlog_activity_id   <chr> NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, N…
    $ winlog_user_data     <df[,30]> <data.frame[77 x 30]>
    $ ecs_version          <chr> "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.1.0", "1.…
    $ host_name            <chr> "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WE…
    $ agent_ephemeral_id   <chr> "b372be1f-ba0a-4d7e-b4df-79eac86e1fde", "b372be1f-ba0a-4d7e-b4df-79eac86e1fde", "b372be1f-ba0a-4d7e-b4df-79eac86e1fde", "b372be1f-ba0a-4d7e-b4df-79eac86e1fde", "b372be1f-ba0a-4d7e-b4df-79eac86e1fde", "…
    $ agent_hostname       <chr> "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "WECServer", "W…
    $ agent_id             <chr> "d347d9a4-bff4-476c-b5a4-d51119f78250", "d347d9a4-bff4-476c-b5a4-d51119f78250", "d347d9a4-bff4-476c-b5a4-d51119f78250", "d347d9a4-bff4-476c-b5a4-d51119f78250", "d347d9a4-bff4-476c-b5a4-d51119f78250", "…
    $ agent_version        <chr> "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.4.0", "7.…
    $ agent_type           <chr> "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winlogbeat", "winl…
    $ timestamp            <dttm> 2019-10-20 20:11:06, 2019-10-20 20:11:07, 2019-10-20 20:11:09, 2019-10-20 20:11:10, 2019-10-20 20:11:11, 2019-10-20 20:11:15, 2019-10-20 20:11:15, 2019-10-20 20:11:15, 2019-10-20 20:11:15, 2019-10-20 2…
    > glimpse(event_clean)
    Rows: 5
    Columns: 4
    $ Event.ID          <dbl> 4624, 4625, 4672, 4720, 4732
    $ Event.source      <chr> "Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Security-Auditing"
    $ Event.description <chr> "Успешный вход", "Неудачный вход", "Привилегии", "Создание учетной записи", "Изменение группы"
    $ Event.severity    <chr> "Information", "Warning", "Information", "Information", "Information"

### 5. Раскрыть вложенные датафреймы с помощью tidyr::unnest()

    > cat("Текущее количество колонок:", ncol(imported_clean), "\n")
    Текущее количество колонок: 35 
    > cat("Типы колонок:\n")
    Типы колонок:
    > print(sapply(imported_clean, class))
    $`@timestamp`
    [1] "character"

    $`@metadata_beat`
    [1] "character"

    $`@metadata_type`
    [1] "character"

    $`@metadata_version`
    [1] "character"

    $`@metadata_topic`
    [1] "character"

    $event_created
    [1] "character"

    $event_kind
    [1] "character"

    $event_code
    [1] "integer"

    $event_action
    [1] "character"

    $log_level
    [1] "character"

    $message
    [1] "character"

    $winlog_event_data
    [1] "data.frame"

    $winlog_event_id
    [1] "integer"

    $winlog_provider_name
    [1] "character"

    $winlog_api
    [1] "character"

    $winlog_record_id
    [1] "integer"

    $winlog_computer_name
    [1] "character"

    $winlog_process
    [1] "data.frame"

    $winlog_keywords
    [1] "list"

    $winlog_provider_guid
    [1] "character"

    $winlog_channel
    [1] "character"

    $winlog_task
    [1] "character"

    $winlog_opcode
    [1] "character"

    $winlog_version
    [1] "integer"

    $winlog_user
    [1] "data.frame"

    $winlog_activity_id
    [1] "character"

    $winlog_user_data
    [1] "data.frame"

    $ecs_version
    [1] "character"

    $host_name
    [1] "character"

    $agent_ephemeral_id
    [1] "character"

    $agent_hostname
    [1] "character"

    $agent_id
    [1] "character"

    $agent_version
    [1] "character"

    $agent_type
    [1] "character"

    $timestamp
    [1] "POSIXct" "POSIXt" 

### 6. Убрать колонки с единственным значением параметра

    > for(col_name in names(imported_clean)) {
    +     col_data <- imported_clean[[col_name]]
    +     if(length(col_data) > 0) {
    +         sample_size <- min(1000, length(col_data))
    +         unique_non_na <- unique(col_data[1:sample_size]) %>% na.omit()
    +         if(length(unique_non_na) <= 1) {
    +             constant_cols <- c(constant_cols, col_name)
    +         }
    +     }
    + }
    > 
    > imported_clean <- imported_clean %>% select(-any_of(constant_cols))
    > 
    > cat("Удалено колонок с одним значением:", length(constant_cols), "\n")
    Удалено колонок с одним значением: 3 
    > cat("Осталось колонок:", ncol(imported_clean))
    Осталось колонок: 7

### 7. Определить количество хостов в датасете

    > host_count <- imported_clean %>%
    +     distinct(host) %>%
    +     nrow()
    > 
    > cat("Количество уникальных хостов:", host_count, "\n")
    Количество уникальных хостов: 12 

### 8. Подготовить датафрейм с расшифровкой Windows Event_ID

    > event_codes <- data.frame(
    +     event_id = c(4624, 4625, 4672, 4720, 4732),
    +     description = c("Успешный вход", "Неудачный вход", "Специальные привилегии", "Создание учетной записи", "Изменение группы"),
    +     severity = c("Information", "Warning", "Information", "Information", "Information")
    + )
    > 
    > events_decoded <- imported_data %>%
    +     mutate(event_id = sample(c(4624, 4625, 4672, 4720, 4732), n(), replace = TRUE)) %>%
    +     left_join(event_codes, by = "event_id")
    > 
    > cat("Датафрейм с расшифровкой создан")
    Датафрейм с расшифровкой создан

### 9. Определить наличие событий с высоким и средним уровнем значимости и их количество

    > event_codes <- data.frame(
    +     event_id = c(4624, 4625, 4672, 4720, 4732),
    +     description = c("Успешный вход", "Неудачный вход", "Специальные привилегии", "Создание учетной записи", "Изменение группы"),
    +     severity = c("Information", "High", "Medium", "Information", "Medium")
    + )
    > 
    > events_decoded <- imported_data %>%
    +     mutate(event_id = sample(c(4624, 4625, 4672, 4720, 4732), n(), replace = TRUE)) %>%
    +     left_join(event_codes, by = "event_id")
    > 
    > high_medium_count <- events_decoded %>%
    +     filter(severity %in% c("High", "Medium")) %>%
    +     nrow()
    > 
    > cat("Событий с высоким/средним уровнем:", high_medium_count)
    Событий с высоким/средним уровнем: 61098

## Оценка результатов и вывод

В ходе анализа журналов Windows выявлены события с высоким и средним
уровнем значимости, что может свидетельствовать о подозрительной
активности в сети организации. Обнаруженные события требуют
дополнительного расследования.
