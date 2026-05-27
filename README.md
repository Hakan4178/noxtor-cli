# noxtor-cli

A minimalist CLI application. Aktif güvenlik açıkları ve bayram sebebi ile yeni özellikler ertelenmiştir.

Arena.c secure

Crypto.c secure

Database.c 2 düşük açık kaldı.

file_tranfer 2 düşük öncelikli açık kaldı

log.c 1 orta 3 düşük öncelikli açık kaldı

main.c 3 Kritik 4 orta 4 düşük açık kaldı

network.c 3 kritik 3 orta açık kaldı

noise.c 2 düşük açık kaldı

stdin_handler.c 3 düşük açık kaldı

ui.c 2 düşük açık kaldı

NOT: Burdaki hiç bir açık komple kriptolojiyi kırmıyor.
Ama zincir halinde kullanırsa metadata sızıntısı ve sqlite bozulması olabilir.

### TODO

- Sertleştirme önlemleri alınmadı
- TOFU önlemleri ve qr desteği 
- Ncurses TUİ
- Kişi ekleme rehber düzenleme modu
- Sqlite denetlenecek
- 5 kişiye kadar grup desteği
- Minimal seccomp denenecek 
- Resmi stable termux sürümü
- Kritik 7 key için memfd_secret() yapısına geçilecek. 
- İnstall.sh yazılacak hem x86 hem termux için.

- Linux kernel 5.15 altı için fallback eklenecek



## Requirements
- GCC 14+
- Linux Kernel
- libsodium-dev

- libsqlite3-dev

- libseccomp-dev

- tor

- obfs4proxy

- snowflake packet


It works experimentally on Termux and natively on x86. 
It’s not finished yet there are still quite a few missing features but at least the messaging mechanics have been thoroughly tested using official Noise XX test vectors.
In summary, it’s a Linux-exclusive, terminal-based messaging tool designed for activists, journalists, or individuals under censorship. Although the necessary security measures for such users haven’t been added yet, critical keys and data are currently being quickly erased from memory.

### Key features:

No central server.

End-to-end encryption via the Noise XX protocol (with forward secrecy, and it’s quite robust).



Compliant with C23 standards, tested under ASan/UBSan—also tested with fanalyser.


## Why not Signal:



Signal requires a prekey server and a centralized infrastructure. 
This project doesn’t touch anything centralized.
It is still in an early stage and not ready for production use. 
I welcome feedback on code quality, architectural decisions, or the threat model, as well as your feature ideas.



To try it out, clone the repository, run `make clean && make release` and then type `./noxtor-cli`
