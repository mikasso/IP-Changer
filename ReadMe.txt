Aby załadować moduł należy uruchomić skrypt LoadModuleFromDNS.sh. 
Skrypt ten na wejście przyjmuję nazwę interfejsu na którym będzie oddziałowywał moduł oraz
listę nazw stron/domen które mają być przekierowywane. Przykładowo polecenie:

./LoadModuleFromDNS.sh enp0s3 moja.pg.edu.pl wp.pl eti.pg.edu.pl interia.pl

Wybiera interfejs sieciowy enp0s3, na którym pakiety będą miały podmieniane adresy IP.
Nastepnię podana jest lista domen z przejściami:

moja.pg.edu.pl -> wp.pl
eti.pg.edu.pl -> interia.pl

Adresy stron z lewej będą przekierowywane do adresow stron po prawej.
Czyli wpisując ,np. moja.pg.edu.pl w przeglądarce powinna się otworzyć strona wp.pl.

Uwaga 1: Jeśli nadal ładuje się strona moja.pg.edu.pl normalnie należy wyczyści cache przęglądarki lub wejść w sesję incognito/private.

Uwaga 2: Ze względu na to że wysyłane żadania są kierowane z zapytaniem http/https o stronę wwww.moja.pg.edu.pl
występuje niezgodność certyfikatów. Należy zignorować ostrzeżenie przęglądarki o ich niezgodności, bądź wyłączyć ich walidację w ustawieniach przeglądarki.

Uwaga 3: Niektóre strony takie jak ,np. google.com mogą być załadowane zapomocą wielu adresów IP. Należy wówczas wszystkie z nich
przekierować wówczas za pomocą załadowania modułu isnmod ręcznie podając listę adresów ip.  

Innym przykładem weryfikującym działanie modułu może byc uruchomienie programu typu packet sniffer, np. Wireshark. 
Gdy moduł znajduję sie w VM, spingowanie w konsoli moja.pg.edu.pl będzie informować o pingowaniu adresu IP moja.pg.edu.pl,
natomiast w Wiresharku na maszynie hosta wysyłane pakiety ICMP będą miały docelowe i źródłowe adresy IP wp.pl.

Można oczywiście też załadować moduł bezpośrednio bo jego poprzednim skompilowaniu za pomocą make.
Argumenty modułu to:

addr - lista adresów w jednym napisie (czyli między cudzysłowami)
interface_name - nazwa interfejsu 
addr_count - długość list addr

Natomiast zaleca się używanie skryptu ./LoadModuleFromDNS.sh gdyż zabezpiecza on przed błędami przy wprowadzaniu parametrów modułu.