# Практическая работа 7. Использование технологии Yandex Query для
анализа данных сетевой активности.
TrystNB@ya.ru

## Цель работы

1.  Изучить возможности технологии Yandex Query для анализа
    структурированныхнаборов данных
2.  Получить навыки построения аналитического пайплайна для анализа
    данных с помощью сервисов Yandex Cloud
3.  Закрепить практические навыки использования SQL для анализа данных
    сетевой активности в сегментированной корпоративной сети

## Исходные данные

1.  Оепрационная система Windows 11
2.  RStudio
3.  Интерпретатор языка R
4.  Yandex Cloud

## Задание

Используя сервис Yandex Query настроить доступ к данным, хранящимся в
сервисе хранения данных Yandex Object Storage. При помощи
соответствующих SQL запросов ответить на вопросы

## Впоросы

1.  Проверить доступность данных в Yandex Object Storage
2.  Подключить бакет как источник данных для Yandex Query
3.  Известно, что IP адреса внутренней сети начинаются с октетов,
    принадлежащих интервалу \[12-14\]. Определить количество хостов
    внутренней сети, представленных в датасете.
4.  Определить суммарный объем исходящего трафика
5.  Определить суммарный объем входящего трафика

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

### 1. Проверка доступности данных

![](./images/1.png)

### 2. Подключим бакет как источник данных для Yandex Query

1.  Создадим соединение для бакета в S3 хранилище ![](./images/2.png)
2.  Перейдем к настройке привязки данных ![](./images/3.png)
3.  Далее настроим состав и формат данных ![](./images/4.png)
4.  Сделаем первый запрос

<!-- -->

    SELECT
       *
    FROM
       `pr7_dataset`
    LIMIT 100;

![](./images/5.png)

### 3. Определим количество хостов внутренней сети, представленных в датасете.

    SELECT COUNT(DISTINCT ip) as internal_hosts_count
    FROM (
        SELECT dst AS ip FROM `pr7_dataset`
        UNION ALL
        SELECT src AS ip FROM `pr7_dataset`
    )
    WHERE 
        ip LIKE '12.%' OR 
        ip LIKE '13.%' OR 
        ip LIKE '14.%'

![](./images/6.png)

### 4. Определим суммарный объем исходящего трафика

              SELECT SUM(bytes) as total_outgoing_traffic
    FROM `pr7_dataset`
    WHERE 
        (src LIKE '12.%' OR src LIKE '13.%' OR src LIKE '14.%')
        AND NOT
        (dst LIKE '12.%' OR dst LIKE '13.%' OR dst LIKE '14.%')

![](./images/7.png)

### 5. Определитм суммарный объем входящего трафика

              SELECT SUM(bytes) as total_incoming_traffic
    FROM `pr7_dataset`
    WHERE 
        NOT (src LIKE '12.%' OR src LIKE '13.%' OR src LIKE '14.%')
        AND 
        (dst LIKE '12.%' OR dst LIKE '13.%' OR dst LIKE '14.%')

![](./images/8.png)

## Оценка результатов и вывод

В ходе выполнения практической работы были изучены возможности
технологии Yandex Query для анализа структурированных данных.
Приобретены навыки построения аналитического пайплайна с использованием
сервисов Yandex Cloud. Закреплены практические навыки применения SQL для
анализа данных сетевой активности в сегментированной корпоративной сети.
Проведен разведочный анализ данных сетевой активности компании XYZ,
хранящихся в Yandex Object Storage, и получены ответы на поставленные
вопросы.
