# Stateful-TCP
This project presents the source code of Stateful-TCP, which has been accepted by IEEE ACCESS (Stateful-TCP - A New Approach to Accelerate TCP Slow-Start)
# Requirement for the kernel version >= 4.09
1. Put both Makefile and scubic_release.c under the same dir.
2. Compile the s-cubic_release.c file with command "make".
3. You may need to install some libraries as indicated in the cmd, if you failed in executing the second step.
4. If everything goes well, under the same dir you will see several new files generated, scubic_release.ko is one of them.
5. Then install the scubic_release.ko module into your machine by "install scubic_release.ko"
6. No output means that you have successfully installed the module into you system. Otherwise likely memory allocation failed (unlikely though)
7. Run scubic as the congestion control algorithm by "sysctl net.ipv4.tcp_congestion_control=scubic".
8. Double check by "sysctl net.ipv4.tcp_congestion_control", if the output is "scubic", congratulation! 
8. Enjoy the speedup!
