# ebpf-execsnoop

Praćenje pokretanja procesa u Linux jezgru pomoću eBPF-a.
Seminarski rad iz predmeta Operativni sistemi 2, PMF Kragujevac.

Alat se kači na tracepoint `sys_enter_execve` i ispisuje svaki
pokušaj pokretanja programa na sistemu.

## Pokretanje

    sudo apt install -y bpfcc-tools python3-bpfcc
    sudo python3 -u execsnoop.py

Zahteva root i jezgro sa podrskom za eBPF.

## Sadrzaj

- execsnoop.py - alat, C deo za jezgro i Python deo za prikaz
- primeri/pathpretraga.py - demonstracija pretrage kroz PATH
- merenja/ - prikupljeni izlazi i podaci o okruzenju
