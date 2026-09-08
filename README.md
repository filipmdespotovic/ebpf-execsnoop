# ebpf-execsnoop

Praćenje pokretanja procesa u Linux jezgru pomoću eBPF-a.
Seminarski rad iz predmeta Operativni sistemi 2, PMF Kragujevac.

Alat se kači na tracepoint `sys_enter_execve` i ispisuje svaki
pokušaj pokretanja programa na sistemu.
