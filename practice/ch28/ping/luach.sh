gcc -I../../lib  -I./ -o ping main.c  init_v6.c  proc_v4.c readloop.c proc_v6.c send_v4.c send_v6.c sig_alrm.c  ../../libunp.a
sudo ./ping -v ikebo.cn