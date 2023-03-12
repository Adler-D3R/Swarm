# Swarm 🔥

### 1. Overview and Features ⚙️
---

**Swarm is a C Language Flooding Tool made to do pentesting and understand how sockets work.**<br>
**It has been made for educational purposes only. I'm not responsible of damages you could do with this tool.**<br>
**Swarm particularity is its high rate IP and Port Spoofing : each request uses a different identity. It also randomizes other parameters such as SEQ and ACK Numbers or ICMP ECHO IDs.**<br>

**It has 11 Flood Types :**
- Type 1 : SYN [TCP]
- Type 2 : ACK [TCP]
- Type 3 : SYN-ACK [TCP]
- Type 4 : RST [TCP]
- Type 5 : PSH [TCP]
- Type 6 : URG [TCP]
- Type 7 : FIN [TCP]
- Type 8 : FIN-ACK [TCP]
- Type 9 : E-REQUEST [ICMP]
- Type 10 : E-REPLY [ICMP]
- Type 11 : DNS-AMP [UDP]

### 2. Usage ⌨️
---

**Swarm has been made for Linux only.**<br>
**First, you need to compile the programm using `GCC`. To do this, simply type : `[sudo] gcc Main.c -o Swarm`**<br>
**Once done, you can run it using : `[sudo] ./Swarm [ARGS]`.**