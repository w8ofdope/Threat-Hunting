# Практическая работа 8. Использование технологии Yandex DataLens для
анализа данных сетевой активности.
TrystNB@ya.ru

## Цель работы

1.  Изучить возможности технологии Yandex DataLens для визуального
    анализа структурированных наборов данных
2.  Получить навыки визуализации данных для последующего анализа с
    помощью сервисов Yandex Cloud
3.  Получить навыки создания решений мониторинга/SIEM на базе облачных
    продуктов и открытых программных решений
4.  Закрепить практические навыки использования SQL для анализа данных
    сетевой активности в сегментированной корпоративной сети

## Исходные данные

1.  Оепрационная система Windows 11
2.  RStudio
3.  Yandex DataLens

## Задание

Используя сервис Yandex DataLens настроить доступ к Yandex Query,
который Вы использовали в ходе ранее выполненных практических работ, и
визуально представить результаты анализа данных.

## Впоросы

1.  Представить в виде круговой диаграммы соотношение внешнего и
    внутреннего сетевого трафика.
2.  Представить в виде столбчатой диаграммы соотношение входящего и
    исходящего трафика из внутреннего сетвого сегмента.
3.  Построить график активности (линейная диаграмма) объема трафика во
    времени.
4.  Все построенные графики вывести в виде единого дашборда в Yandex
    DataLens.

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

### 1. Настроить подключение к Yandex Query из DataLens

Настроим и проверим подключение Yandex Query из DataLens
![](images/1.png)

Создадим из запроса YandexQuery датасет DataLens. Для этого перетащим из
левой колонки результаты доступных запросов как датасет в правую часть
экрвна. ![](images/2.png)

### 2. Представить в виде круговой диаграммы соотношение внешнего и внутреннего сетевого трафика.

    IF 
        (STARTSWITH([src], "12.") OR STARTSWITH([src], "13.") OR STARTSWITH([src], "14."))
        AND
        (STARTSWITH([dst], "12.") OR STARTSWITH([dst], "13.") OR STARTSWITH([dst], "14."))
    THEN 
        "Internal"
    ELSE 
        "External"
    END

![](images/3.png)

### 3. Представить в виде столбчатой диаграммы соотношение входящего и исходящего трафика из внутреннего сетвого сегмента.

    IF 
        NOT STARTSWITH([src], "12.") 
        AND NOT STARTSWITH([src], "13.") 
        AND NOT STARTSWITH([src], "14.")
        AND 
        (STARTSWITH([dst], "12.") 
         OR STARTSWITH([dst], "13.") 
         OR STARTSWITH([dst], "14."))
    THEN 
        "Входящий"

    ELSEIF 
        (STARTSWITH([src], "12.") 
         OR STARTSWITH([src], "13.") 
         OR STARTSWITH([src], "14."))
        AND 
        (NOT STARTSWITH([dst], "12.") 
         AND NOT STARTSWITH([dst], "13.") 
         AND NOT STARTSWITH([dst], "14."))
    THEN 
        "Исходящий"

    END

![](images/4.png)

### 4. Построить график активности (линейная диаграмма) объема трафика во времени.

    ROUND(FLOAT([timestamp]) / 1000000, 2)

![](images/5.png)

### 5. Все построенные графики вывести в виде единого дашборда в Yandex DataLens.

![](images/6.png) [Ссылка на итоговый
дашборд](https://datalens.ru/rarpptgpkrncc-dashboard-pr8)

## Оценка результатов и вывод

Отчёт написан и оформлен
