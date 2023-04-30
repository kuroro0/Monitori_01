# Monitori_01
Create iptables like rules for processes running.


You can create custom rules, which if a process matches, it is killed. Although in this example the kill syscall is not actually called for the PID, because, ill-informed use of this can cause the system to crash. 
We can also add Packet rules which are applied to the host ports and remote IP and protocol used. These rules are simply converted to respective IPtables format commands, and appended to the rules(the actual appending is ignored because it a simple rule mistake can cause problems)

Refer to the rules_example.txt to see what the rules look like.

NOTE: CPU usage is calculated by total time spent in running state in 2 seconds.

Also to be noted the rules are a sort of linked list, which are arranged according to priority. 

THIS IS DONE IN VIEW OF MY FINAL YEAR PROJECT(19BCE1344)
